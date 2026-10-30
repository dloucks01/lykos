/* seal - wrap each payload of a spool file in a sealed frame (payload + 16-byte tag)
 * input: "SPL1" then entries [len u16 LE][payload]                    */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TAG_LEN 16

static void compute_tag(unsigned char *tag, const unsigned char *p, uint16_t len)
{
    uint32_t h = 0x811c9dc5u;
    for (uint16_t i = 0; i < len; i++)
        h = (h ^ p[i]) * 0x01000193u;
    for (int i = 0; i < TAG_LEN; i++) {
        tag[i] = (unsigned char)(h >> ((i % 4) * 8));
        h = h * 33 + (uint32_t)i;
    }
}

static unsigned char *seal_frame(const unsigned char *payload, uint16_t len, uint16_t *out_len)
{
    uint16_t total = len + TAG_LEN;
    unsigned char *out = malloc(total);
    if (!out)
        return NULL;
    memcpy(out, payload, len);
    compute_tag(out + len, payload, len);
    *out_len = total;
    return out;
}

int main(int argc, char **argv)
{
    static unsigned char buf[1 << 17];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <spool>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 4 || memcmp(buf, "SPL1", 4) != 0) {
        fprintf(stderr, "not a spool\n");
        return 1;
    }
    size_t off = 4;
    int frames = 0;
    while (off + 2 <= n) {
        uint16_t len = (uint16_t)(buf[off] | (buf[off + 1] << 8));
        off += 2;
        if (len > n - off)
            break;
        uint16_t flen;
        unsigned char *fr = seal_frame(buf + off, len, &flen);
        if (!fr)
            break;
        printf("frame %d: %u bytes, tag %02x%02x\n", frames++, flen, fr[flen - 2], fr[flen - 1]);
        free(fr);
        off += len;
    }
    return 0;
}
