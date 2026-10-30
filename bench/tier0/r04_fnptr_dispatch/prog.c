/* msgproc - process a message batch through a handler table
 * format: 0x7f 'M' 'S' 'G' then messages [type u8][len u16 LE][payload] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define STORE_SLOT 32
#define STORE_MAX 256

struct ctx {
    unsigned char *store;
    size_t stored;
    unsigned pings;
};

typedef int (*handler_fn)(struct ctx *, const unsigned char *, uint16_t);

static int h_ping(struct ctx *c, const unsigned char *p, uint16_t len)
{
    (void)p; (void)len;
    c->pings++;
    return 0;
}

static int h_info(struct ctx *c, const unsigned char *p, uint16_t len)
{
    (void)c;
    printf("info: %.*s\n", (int)len, (const char *)p);
    return 0;
}

static int h_store(struct ctx *c, const unsigned char *p, uint16_t len)
{
    if (len > STORE_MAX)
        return -1;
    memcpy(c->store, p, len);
    c->stored = len;
    return 0;
}

static int h_clear(struct ctx *c, const unsigned char *p, uint16_t len)
{
    (void)p; (void)len;
    memset(c->store, 0, STORE_SLOT);
    c->stored = 0;
    return 0;
}

static const handler_fn handlers[] = { h_ping, h_info, h_clear, h_store };
#define NHANDLERS (sizeof handlers / sizeof handlers[0])

int main(int argc, char **argv)
{
    static unsigned char buf[16384];
    struct ctx c = { 0 };
    if (argc < 2) {
        fprintf(stderr, "usage: %s <batch>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 4 || memcmp(buf, "\x7fMSG", 4) != 0) {
        fprintf(stderr, "bad magic\n");
        return 1;
    }
    c.store = calloc(1, STORE_SLOT);
    size_t off = 4;
    while (off + 3 <= n) {
        uint8_t type = buf[off];
        uint16_t len = (uint16_t)(buf[off + 1] | (buf[off + 2] << 8));
        off += 3;
        if (len > n - off)
            break;
        if (type < NHANDLERS && handlers[type](&c, buf + off, len) != 0)
            fprintf(stderr, "handler %u rejected message\n", type);
        off += len;
    }
    printf("pings=%u stored=%zu\n", c.pings, c.stored);
    free(c.store);
    return 0;
}
