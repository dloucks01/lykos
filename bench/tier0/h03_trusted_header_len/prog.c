/* reasm - reassemble a chunked message and print its digest
 * format: "CHNK" total_len(u32 LE) then chunks [clen u16 LE][data]
 * terminated by a zero-length chunk                                  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_TOTAL (1u << 20)

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static unsigned char *reassemble(const unsigned char *p, size_t n, uint32_t total, size_t *out_len)
{
    unsigned char *msg = malloc(total ? total : 1);
    size_t have = 0, off = 0;
    if (!msg)
        return NULL;
    while (off + 2 <= n) {
        uint16_t clen = (uint16_t)(p[off] | (p[off + 1] << 8));
        off += 2;
        if (clen == 0)
            break;
        if (clen > n - off) {
            free(msg);
            return NULL;
        }
        memcpy(msg + have, p + off, clen);
        have += clen;
        off += clen;
    }
    *out_len = have;
    return msg;
}

int main(int argc, char **argv)
{
    static unsigned char buf[65536];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 8 || memcmp(buf, "CHNK", 4) != 0) {
        fprintf(stderr, "bad header\n");
        return 1;
    }
    uint32_t total = rd32(buf + 4);
    if (total > MAX_TOTAL) {
        fprintf(stderr, "message too large\n");
        return 1;
    }
    size_t len = 0;
    unsigned char *msg = reassemble(buf + 8, n - 8, total, &len);
    if (!msg) {
        fprintf(stderr, "reassembly failed\n");
        return 1;
    }
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++)
        h = (h ^ msg[i]) * 16777619u;
    printf("reassembled %zu/%u bytes, fnv1a=%08x\n", len, total, h);
    free(msg);
    return 0;
}
