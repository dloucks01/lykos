/* fontmeasure - measure text widths with a bitmap font
 * format: "BFNT" n_glyphs(u8) widths[n_glyphs] text_len(u8) text[]   */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct font {
    unsigned n_glyphs;
    uint8_t *widths;
};

static unsigned measure(const struct font *fnt, const uint8_t *text, size_t len)
{
    unsigned total = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t g = text[i];
        total += fnt->widths[g];
    }
    return total;
}

int main(int argc, char **argv)
{
    static uint8_t buf[1024];
    struct font fnt;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <font+text>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 5 || memcmp(buf, "BFNT", 4) != 0) {
        fprintf(stderr, "not a font\n");
        return 1;
    }
    fnt.n_glyphs = buf[4];
    if (fnt.n_glyphs == 0 || 5 + fnt.n_glyphs + 1 > n) {
        fprintf(stderr, "bad glyph table\n");
        return 1;
    }
    fnt.widths = malloc(fnt.n_glyphs);
    memcpy(fnt.widths, buf + 5, fnt.n_glyphs);
    size_t off = 5 + fnt.n_glyphs;
    size_t text_len = buf[off++];
    if (text_len > n - off) {
        fprintf(stderr, "text truncated\n");
        free(fnt.widths);
        return 1;
    }
    printf("%u glyphs, text width %u px\n", fnt.n_glyphs, measure(&fnt, buf + off, text_len));
    free(fnt.widths);
    return 0;
}
