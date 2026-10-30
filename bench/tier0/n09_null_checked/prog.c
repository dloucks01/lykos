/* msgdump + blobcat (fixed) - missing decoders are skipped and the payload allocation is checked */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct decoder {
    const char *name;
};

static const struct decoder text_dec = {"text"};
static const struct decoder *decoders[4] = {&text_dec, NULL, &text_dec, NULL};

int main(int argc, char **argv)
{
    uint8_t buf[512];
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
    if (n < 13 || memcmp(buf, "NUL1", 4) != 0)
        return 1;
    uint64_t want = 0;
    for (int i = 11; i >= 4; i--)
        want = (want << 8) | buf[i];
    if (want == 0 || want > (1u << 20)) {
        fprintf(stderr, "bad size\n");
        return 1;
    }
    char *copy = malloc(want);
    if (!copy) {
        fprintf(stderr, "cannot allocate %llu bytes\n", (unsigned long long)want);
        return 1;
    }
    copy[0] = '\0';
    for (size_t off = 12; off < n; off++) {
        uint8_t type = buf[off] & 3;
        const struct decoder *d = decoders[type];
        if (d == NULL)
            continue;
        printf("%s ", d->name);
    }
    printf("\n");
    free(copy);
    return 0;
}
