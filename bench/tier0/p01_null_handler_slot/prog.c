/* msgdump - decode a message log; each record names its decoder by type id
 * format: "MLG1" then records [type u8][len u8][len bytes] */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct decoder {
    const char *name;
    void (*show)(const uint8_t *p, int len);
};

static void show_text(const uint8_t *p, int len) { printf("text: %.*s\n", len, (const char *)p); }
static void show_hex(const uint8_t *p, int len)
{
    printf("hex:");
    for (int i = 0; i < len; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

static const struct decoder text_dec = {"text", show_text};
static const struct decoder hex_dec = {"hex", show_hex};

/* types 0..7 are reserved; only some have decoders yet */
static const struct decoder *decoders[8] = {&text_dec, &hex_dec, NULL, &hex_dec, NULL, NULL, &text_dec, NULL};

int main(int argc, char **argv)
{
    uint8_t buf[512];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <log>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 4 || memcmp(buf, "MLG1", 4) != 0)
        return 1;
    size_t off = 4;
    while (off + 2 <= n) {
        uint8_t type = buf[off], len = buf[off + 1];
        off += 2;
        if (off + len > n || type >= 8)
            break;
        const struct decoder *d = decoders[type];
        printf("[%s] ", d->name);
        d->show(buf + off, len);
        off += len;
    }
    return 0;
}
