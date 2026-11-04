"""Double-fetch (CWE-367) and uninitialized-pointer (CWE-824) detectors — precision-first."""
from lykos.analyze.race_scan import find_double_fetch, find_uninit_ptr


def test_double_fetch_fires_on_kernel_double_copy_from_user():
    src = """
    long ioctl_handler(struct file* f, unsigned long arg) {
        struct hdr __user* uptr = (struct hdr __user*)arg;
        u32 len;
        struct msg* m;
        if (get_user(len, &uptr->len))
            return -EFAULT;
        if (len > MAX_LEN)
            return -EINVAL;
        m = kmalloc(sizeof(*m) + len, GFP_KERNEL);
        if (copy_from_user(m, uptr, sizeof(*m) + len))
            return -EFAULT;
        return process(m);
    }
    """
    hits = find_double_fetch(src)
    assert any(h.field == "uptr" for h in hits)


def test_double_fetch_fires_on_header_then_full_copy_from_user():
    src = """
    static int set_cfg(void __user* uarg) {
        struct cfg_hdr hdr;
        if (copy_from_user(&hdr, uarg, sizeof(hdr)))
            return -EFAULT;
        if (hdr.len > CFG_MAX)
            return -EINVAL;
        if (copy_from_user(kbuf, uarg, sizeof(hdr) + hdr.len))
            return -EFAULT;
        return apply(kbuf);
    }
    static int two_fields(void __user* u) {     /* independent fetches -> no TOCTOU */
        int a, b;
        if (copy_from_user(&a, u, 4)) return -EFAULT;
        if (copy_from_user(&b, u + 4, 4)) return -EFAULT;
        return a + b;
    }
    """
    hits = find_double_fetch(src)
    assert [(h.function, h.field) for h in hits] == [("set_cfg", "uarg")]


def test_double_fetch_fires_on_shared_mapping_check_then_refetch():
    src = """
    int consume(int fd, char* dst) {
        struct ring* shm;
        shm = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
        if (shm->len > 64) return -1;
        memcpy(dst, shm->data, shm->len);
        return 0;
    }
    """
    hits = find_double_fetch(src)
    assert any(h.field == "shm->len" for h in hits)


def test_double_fetch_ignores_correct_validate_then_use():
    # ordinary process memory: re-reading a validated field is CORRECT, whatever it is named
    src = """
    int handle(user_req_t* user, request_t* req) {
        if (req->len > 64) return -1;
        memcpy(dst, req->data, req->len);
        if (user->len > MAX) return -1;
        char* d = malloc(user->len);
        return 0;
    }
    int k(ctx_t* context) {
        if (context->u2u->n > 4) return 0;
        memcpy(a, b, context->u2u->n);
        return 1;
    }
    int priv(int fd) {
        hdr_t* h = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (h->len > 64) return -1;
        memcpy(dst, h->data, h->len);
        return 0;
    }
    """
    assert find_double_fetch(src) == []


def test_double_fetch_ignores_trusted_single_read():
    src = """
    int f(cfg_t* cfg) {
        if (cfg->size > 0) { total += cfg->size; }
        return 0;
    }
    int g(local_t* s) { int n = s->count; return n; }
    """
    assert find_double_fetch(src) == []


def test_uninit_ptr_fires_on_deref_before_assign():
    src = """
    void f(void) {
        char* p;
        p->field = 1;     /* deref before any assignment -> uninitialized pointer */
    }
    void g(int n) {
        int *q;
        *q = n;
    }
    """
    hits = find_uninit_ptr(src)
    assert {h.ptr for h in hits} == {"p", "q"}


def test_uninit_ptr_clears_on_assignment():
    src = """
    void g(void) {
        char* p;
        p = malloc(16);
        p[0] = 'x';       /* assigned first -> not uninitialized */
    }
    void h(void) {
        int* q;
        get(&q);          /* &q passed to initializer -> cleared */
        *q = 3;
    }
    void loop(node_t* head) {
        node_t* it;
        list_for_each(it, head) {   /* macro assigns it */
            it->x = 0;
        }
    }
    """
    assert find_uninit_ptr(src) == []


def test_uninit_ptr_ignores_member_access_and_sibling_redeclaration():
    src = """
    void dev(void) {
        union { RDPDR_DEVICE* dev; RDPDR_DRIVE* drive; } device;
        RDPDR_DRIVE* drive;
        device.drive->Path = strdup("x");
        cnv.drive->Path = 0;
        client->drive->settings = 0;
        drive = device.drive;
        drive->Path = 0;
    }
    void sib(int a) {
        if (a) {
            WCHAR* wc;
            wc = alloc();
            wc[0] = 0;
        } else {
            WCHAR* wc;
            wc = alloc();
            wc[0] = 1;
        }
    }
    int mul(int a, int* b) {
        int* r;
        int x = a * r_count;
        static char* s;
        s[0] = 0;          /* static locals are zero-initialised */
        return sizeof(*r);  /* unevaluated */
    }
    """
    assert find_uninit_ptr(src) == []


def test_reported_lines_are_one_based_file_lines():
    src = ("/* header */\n"           # 1
           "#include <x.h>\n"          # 2
           "\n"                        # 3
           "/* a\n   multi-line\n   comment */\n"   # 4-6
           "void f(void)\n"            # 7
           "{\n"                       # 8
           "    char* p;\n"            # 9
           "    /* x */\n"             # 10
           "    p->field = 1;\n"       # 11
           "}\n"
           "int g(int fd, char* dst)\n"                                      # 13
           "{\n"                                                             # 14
           "    struct ring* shm = mmap(0, 9, 1, MAP_SHARED, fd, 0);\n"      # 15
           "    if (shm->len > 64)\n"                                        # 16
           "        return -1;\n"                                            # 17
           "    memcpy(dst, shm->data, shm->len);\n"                         # 18
           "    return 0;\n"
           "}\n")
    (u,) = find_uninit_ptr(src)
    assert (u.decl_line, u.use_line) == (9, 11)
    (d,) = find_double_fetch(src)
    assert (d.check_line, d.use_line) == (16, 18)


def test_preprocessor_branches_do_not_unbalance_or_leak():
    # `#if 0` code is dead; alternative #ifdef branches each opening a brace must not let the
    # function body swallow the next function's K&R-style parameter declaration.
    src = """
    void a(int x) {
    #if 0
        struct tp* tp;
        tp->id = 0;
    #endif
    #ifdef A
        if (x) {
    #else
        if (!x) {
    #endif
            x++;
        }
    }
    int b(pd)
        direntry **pd;
    {
        *pd = 0;
        return 0;
    }
    """
    assert find_uninit_ptr(src) == []
