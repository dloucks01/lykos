/* tblload - load a fixed-width record table and print a column summary
 * format: "TBL0" rows(u32 LE) rowsize(u32 LE) then rows*rowsize bytes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_FILE (1 << 20)

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static unsigned char *load_table(const unsigned char *p, size_t n, uint32_t rows,
                                 uint32_t rowsize, uint32_t *loaded)
{
    uint32_t total = rows * rowsize;
    unsigned char *tbl = malloc(total ? total : 1);
    if (!tbl)
        return NULL;
    const unsigned char *end = p + n;
    uint32_t r;
    for (r = 0; r < rows; r++) {
        if ((size_t)(end - p) < rowsize)
            break;
        memcpy(tbl + (size_t)r * rowsize, p, rowsize);
        p += rowsize;
    }
    *loaded = r;
    return tbl;
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
    if (n < 12 || memcmp(buf, "TBL0", 4) != 0) {
        fprintf(stderr, "not a table\n");
        free(buf);
        return 1;
    }
    uint32_t rows = rd32(buf + 4), rowsize = rd32(buf + 8), loaded = 0;
    if (rowsize == 0 || rowsize > 4096) {
        fprintf(stderr, "bad row size\n");
        free(buf);
        return 1;
    }
    unsigned char *tbl = load_table(buf + 12, n - 12, rows, rowsize, &loaded);
    if (!tbl) {
        free(buf);
        return 1;
    }
    unsigned sum = 0;
    for (uint32_t r = 0; r < loaded; r++)
        sum += tbl[(size_t)r * rowsize];
    printf("%u/%u rows loaded, first-column sum %u\n", loaded, rows, sum);
    free(tbl);
    free(buf);
    return 0;
}
