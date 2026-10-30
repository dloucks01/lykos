/* statsum - summarise a sample file and print the per-channel mean
 * format: "STS1" then u8 channel count, then per channel: u16 LE n, then n x u16 LE samples */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int rd16(FILE *f, uint16_t *v)
{
    int lo = fgetc(f), hi = fgetc(f);
    if (lo == EOF || hi == EOF)
        return -1;
    *v = (uint16_t)(lo | (hi << 8));
    return 0;
}

static int channel_mean(FILE *f, int ch)
{
    uint16_t n, s;
    unsigned sum = 0;
    if (rd16(f, &n) != 0)
        return -1;
    for (unsigned i = 0; i < n; i++) {
        if (rd16(f, &s) != 0)
            return -1;
        sum += s;
    }
    unsigned mean = sum / n;
    printf("channel %d: %u samples, mean %u\n", ch, (unsigned)n, mean);
    return 0;
}

int main(int argc, char **argv)
{
    char magic[4];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <samples>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "STS1", 4) != 0) {
        fprintf(stderr, "not a sample file\n");
        fclose(f);
        return 1;
    }
    int chans = fgetc(f);
    if (chans == EOF || chans > 8) {
        fclose(f);
        return 1;
    }
    for (int c = 0; c < chans; c++)
        if (channel_mean(f, c) != 0)
            break;
    fclose(f);
    return 0;
}
