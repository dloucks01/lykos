/* heappoison.c -- an LD_PRELOAD heap-error detector (Electric-Fence / ASan-lite).
 *
 * Replaces malloc/calloc/realloc/free with a guard-page allocator so heap bugs fault at the
 * exact offending access instead of silently corrupting:
 *   - heap buffer overflow  : user data ends flush against a PROT_NONE guard page -> a write
 *                             (or read) past the end faults immediately.
 *   - use-after-free        : freed regions are mprotect(PROT_NONE)'d and quarantined (not
 *                             unmapped), so any later access faults.
 *   - double free / wild free: caught in free() via a per-allocation header magic.
 *   - memory leak           : live allocations at exit are reported.
 *
 * Findings are written as one JSON line each to $LYKOS_HEAP_REPORT (async-signal-safe write in
 * the fault handler). On a faulting bug we report and _exit(86); double/wild free and leaks are
 * reported without aborting. Falls back to the real allocator when mmap fails or for huge sizes,
 * so it degrades safely on real programs. Build: cc -shared -fPIC -O2 heappoison.c -o heappoison.so -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>

#define PAGE 4096UL
#define HDR_MAGIC 0xA110C8EDU
#define FREED_MAGIC 0xDEADF8EEU
#define MAX_TRACK (1u << 18)      /* live+quarantined regions tracked */
#define QUARANTINE 4096           /* freed regions kept mapped (PROT_NONE) before munmap */
#define BIG (16UL * 1024 * 1024)  /* fall back to real malloc above this size */

struct region { void *user, *base; size_t maplen, size; unsigned state; };
static struct region g_tab[MAX_TRACK];
static size_t g_n;
static void *g_quar[QUARANTINE]; static size_t g_quar_head, g_quar_count;
static int g_fd = -1;
static volatile int g_lock;

static void *(*real_malloc)(size_t);
static void  (*real_free)(void *);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);

static void lock(void)   { while (__sync_lock_test_and_set(&g_lock, 1)) { } }
static void unlock(void) { __sync_lock_release(&g_lock); }

/* async-signal-safe: emit one JSON finding line */
static void emit(const char *kind, unsigned long addr, unsigned long size, const char *fn)
{
    if (g_fd < 0) return;
    char b[256]; int p = 0;
    const char *pre = "{\"error\":\"";
    while (*pre) b[p++] = *pre++;
    while (*kind) b[p++] = *kind++;
    const char *m = "\",\"addr\":\"0x";        /* quoted -- a bare 0x.. is not valid JSON */
    while (*m) b[p++] = *m++;
    char hx[16]; int h = 0; unsigned long a = addr;
    if (!a) hx[h++] = '0';
    while (a) { int d = a & 0xf; hx[h++] = d < 10 ? '0' + d : 'a' + d - 10; a >>= 4; }
    while (h) b[p++] = hx[--h];
    const char *s = "\",\"size\":"; while (*s) b[p++] = *s++;
    char dc[24]; int c = 0; unsigned long z = size;
    if (!z) dc[c++] = '0';
    while (z) { dc[c++] = '0' + (z % 10); z /= 10; }
    while (c) b[p++] = dc[--c];
    const char *f = ",\"func\":\""; while (*f) b[p++] = *f++;
    while (*fn) b[p++] = *fn++;
    b[p++] = '"'; b[p++] = '}'; b[p++] = '\n';
    (void)!write(g_fd, b, p);
}

/* bootstrap arena: dlsym() may call calloc before real_malloc is resolved (re-entrancy) */
static char g_boot[1 << 16]; static size_t g_boot_off; static int g_in_init;
static void *boot_alloc(size_t n)
{
    n = (n + 15) & ~15UL;
    if (g_boot_off + n > sizeof g_boot) return NULL;
    void *p = g_boot + g_boot_off; g_boot_off += n; return p;
}
static int is_boot(void *p) { return (char *)p >= g_boot && (char *)p < g_boot + sizeof g_boot; }

static void init(void)
{
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    const char *rp = getenv("LYKOS_HEAP_REPORT");
    if (rp) g_fd = open(rp, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

static struct region *find(void *p)   /* region whose mapping contains p */
{
    for (size_t i = 0; i < g_n; i++) {
        struct region *r = &g_tab[i];
        if (r->base && (char *)p >= (char *)r->base &&
            (char *)p < (char *)r->base + r->maplen)
            return r;
    }
    return NULL;
}
static struct region *by_user(void *u)
{
    for (size_t i = 0; i < g_n; i++)
        if (g_tab[i].user == u && g_tab[i].state == HDR_MAGIC) return &g_tab[i];
    return NULL;
}

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)uc;
    unsigned long fa = (unsigned long)si->si_addr;
    struct region *r = find(si->si_addr);
    if (r) {
        if (r->state == FREED_MAGIC) emit("use-after-free", fa, r->size, "access");
        else emit("heap-buffer-overflow", fa, r->size, "access");
        _exit(86);
    }
    signal(sig, SIG_DFL);        /* not ours: let it crash normally */
    raise(sig);
}

__attribute__((constructor)) static void setup(void)
{
    if (!real_malloc) init();
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
}

static void *guarded(size_t size)
{
    if (!real_malloc) {                         /* resolve real allocator once, safely */
        if (g_in_init) return boot_alloc(size);
        g_in_init = 1; init(); g_in_init = 0;
        if (!real_malloc) return boot_alloc(size);
    }
    if (size == 0) size = 1;
    if (size >= BIG || g_n >= MAX_TRACK) return real_malloc(size);
    size_t asize = (size + 15) & ~15UL;                 /* 16-byte align the user end */
    size_t user_pages = (asize + PAGE - 1) & ~(PAGE - 1);
    size_t maplen = user_pages + PAGE;                  /* + trailing guard page */
    char *base = mmap(NULL, maplen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) return real_malloc(size);
    mprotect(base + user_pages, PAGE, PROT_NONE);       /* guard: overflow faults here */
    void *user = base + user_pages - asize;             /* user data ends flush at the guard */
    lock();
    struct region *r = &g_tab[g_n++];
    r->user = user; r->base = base; r->maplen = maplen; r->size = size; r->state = HDR_MAGIC;
    unlock();
    return user;
}

void *malloc(size_t size) { return guarded(size); }

void *calloc(size_t n, size_t sz)
{
    size_t total = n * sz;
    if (sz && total / sz != n) return NULL;             /* overflow in the size computation */
    void *p = guarded(total);
    return p;                                           /* mmap memory is already zeroed */
}

void free(void *p)
{
    if (!p) return;
    if (is_boot(p)) return;                     /* bootstrap arena: never freed */
    if (!real_free) init();
    lock();
    struct region *r = find(p);
    if (!r) { unlock(); real_free(p); return; }         /* not ours (pre-init / big) */
    if (r->user != p) { unlock(); emit("invalid-free", (unsigned long)p, 0, "free"); return; }
    if (r->state == FREED_MAGIC) { unlock(); emit("double-free", (unsigned long)p, r->size, "free"); return; }
    r->state = FREED_MAGIC;
    mprotect(r->base, r->maplen, PROT_NONE);            /* UAF: any later access faults */
    /* quarantine: keep it mapped (PROT_NONE) a while so UAF is caught, then reclaim */
    if (g_quar_count == QUARANTINE) {
        void *old = g_quar[g_quar_head];
        struct region *o = find(old);
        if (o) { munmap(o->base, o->maplen); o->base = NULL; }
        g_quar_head = (g_quar_head + 1) % QUARANTINE; g_quar_count--;
    }
    g_quar[(g_quar_head + g_quar_count) % QUARANTINE] = p; g_quar_count++;
    unlock();
}

void *realloc(void *p, size_t size)
{
    if (!p) return guarded(size);
    if (size == 0) { free(p); return NULL; }
    if (is_boot(p)) { void *np = guarded(size); if (np) memcpy(np, p, size); return np; }
    lock();
    struct region *r = by_user(p);
    unlock();
    if (!r) { if (!real_realloc) init(); return real_realloc(p, size); }
    void *np = guarded(size);
    if (np) memcpy(np, p, r->size < size ? r->size : size);
    free(p);
    return np;
}

__attribute__((destructor)) static void fini(void)
{
    /* leak reporting is opt-in: at exit every still-live allocation looks "leaked" (including
     * benign libc-internal buffers), so only emit when explicitly asked ($LYKOS_HEAP_LEAKS). */
    if (!getenv("LYKOS_HEAP_LEAKS")) return;
    for (size_t i = 0; i < g_n; i++)
        if (g_tab[i].state == HDR_MAGIC)
            emit("memory-leak", (unsigned long)g_tab[i].user, g_tab[i].size, "exit");
}
