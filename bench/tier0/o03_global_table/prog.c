/* palpatch - apply a palette patch file to the default 64-colour palette
 * format: "PAL" count(u8) then count x [index u8][r][g][b]             */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NCOLORS 64

static uint32_t palette[NCOLORS];

static void init_palette(void)
{
    for (int i = 0; i < NCOLORS; i++)
        palette[i] = (uint32_t)(i * 4) * 0x010101u;
}

static void set_color(uint8_t idx, uint8_t r, uint8_t g, uint8_t b)
{
    palette[idx] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
}

int main(int argc, char **argv)
{
    unsigned char hdr[4], ent[4];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <patch>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    if (fread(hdr, 1, 4, f) != 4 || memcmp(hdr, "PAL", 3) != 0) {
        fprintf(stderr, "bad patch\n");
        fclose(f);
        return 1;
    }
    unsigned count = hdr[3];
    if (count > NCOLORS) {
        fprintf(stderr, "too many entries\n");
        fclose(f);
        return 1;
    }
    init_palette();
    for (unsigned i = 0; i < count; i++) {
        if (fread(ent, 1, 4, f) != 4)
            break;
        set_color(ent[0], ent[1], ent[2], ent[3]);
    }
    fclose(f);
    uint32_t h = 0;
    for (int i = 0; i < NCOLORS; i++)
        h = h * 31 + palette[i];
    printf("palette hash %08x, entry0 #%06x\n", h, palette[0]);
    return 0;
}
