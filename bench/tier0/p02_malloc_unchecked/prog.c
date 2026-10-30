/* blobcat - unpack a blob container: header gives the payload size, payload follows
 * format: "BLB1" then u64 LE declared size, then the payload bytes */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

int main(int argc, char **argv)
{
    uint8_t hdr[12];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <blob>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    if (fread(hdr, 1, sizeof hdr, f) != sizeof hdr || memcmp(hdr, "BLB1", 4) != 0) {
        fclose(f);
        return 1;
    }
    uint64_t size = rd64(hdr + 4);
    if (size == 0) {
        printf("empty payload\n");
        fclose(f);
        return 0;
    }
    char *payload = malloc(size);
    payload[0] = '\0';
    size_t got = fread(payload, 1, size < 4096 ? size : 4096, f);
    printf("payload (%zu of %llu bytes): ", got, (unsigned long long)size);
    fwrite(payload, 1, got, stdout);
    printf("\n");
    free(payload);
    fclose(f);
    return 0;
}
