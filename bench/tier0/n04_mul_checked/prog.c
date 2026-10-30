/* tblload2 - load a record table, then seal each row as a frame
 * format: "TBL1" rows(u32 LE) rowsize(u32 LE) then rows*rowsize bytes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_FILE (1 << 20)
#define MAX_TABLE (16u << 20)
#define TAG_LEN 16

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static unsigned char *seal(const unsigned char *row, uint32_t len, size_t *out_len)
{
    size_t total = (size_t)len + TAG_LEN;
    unsigned char *out = malloc(total);
    if (!out)
        return NULL;
    memcpy(out, row, len);
    memset(out + len, 0xa5, TAG_LEN);
    *out_len = total;
    return out;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <table>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    unsigned char *buf = malloc(MAX_FILE);
    size_t n = fread(buf, 1, MAX_FILE, f);
    fclose(f);
    if (n < 12 || memcmp(buf, "TBL1", 4) != 0) {
        fprintf(stderr, "not a table\n");
        free(buf);
        return 1;
    }
    uint32_t rows = rd32(buf + 4), rowsize = rd32(buf + 8), total;
    if (rowsize == 0 || __builtin_mul_overflow(rows, rowsize, &total) || total > MAX_TABLE) {
        fprintf(stderr, "bad table geometry\n");
        free(buf);
        return 1;
    }
    unsigned char *tbl = malloc(total ? total : 1);
    uint32_t r;
    for (r = 0; r < rows && (size_t)rowsize <= n - 12 - (size_t)r * rowsize; r++)
        memcpy(tbl + (size_t)r * rowsize, buf + 12 + (size_t)r * rowsize, rowsize);
    size_t frames = 0;
    for (uint32_t i = 0; i < r; i++) {
        size_t flen;
        unsigned char *fr = seal(tbl + (size_t)i * rowsize, rowsize, &flen);
        if (!fr)
            break;
        frames += flen;
        free(fr);
    }
    printf("%u/%u rows, %zu sealed bytes\n", r, rows, frames);
    free(tbl);
    free(buf);
    return 0;
}
