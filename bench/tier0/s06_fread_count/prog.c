/* imgsum - per-row checksums for a raw 8-bit greyscale image
 * header: "IMG1" width(u16 LE) height(u16 LE), then width*height bytes */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_HEIGHT 1024

static int read_u16(FILE *f, uint16_t *out)
{
    int lo = fgetc(f), hi = fgetc(f);
    if (lo == EOF || hi == EOF)
        return -1;
    *out = (uint16_t)(lo | (hi << 8));
    return 0;
}

static uint32_t adler(const unsigned char *p, size_t n)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; i++) {
        a = (a + p[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

static int process_rows(FILE *f, uint16_t width, uint16_t height)
{
    unsigned char row[256];
    for (uint16_t y = 0; y < height; y++) {
        size_t got = fread(row, 1, width, f);
        if (got != width) {
            fprintf(stderr, "row %u truncated\n", y);
            return -1;
        }
        printf("row %3u: %08x\n", y, adler(row, got));
    }
    return 0;
}

int main(int argc, char **argv)
{
    char magic[4];
    uint16_t w, h;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <image.raw>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "IMG1", 4) != 0 ||
        read_u16(f, &w) || read_u16(f, &h)) {
        fprintf(stderr, "bad header\n");
        fclose(f);
        return 1;
    }
    if (w == 0 || h == 0 || h > MAX_HEIGHT) {
        fprintf(stderr, "bad dimensions %ux%u\n", w, h);
        fclose(f);
        return 1;
    }
    int rc = process_rows(f, w, h);
    fclose(f);
    return rc == 0 ? 0 : 1;
}
