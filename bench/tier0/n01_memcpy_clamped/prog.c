/* tlvdump2 - print the fields of a TLV-encoded device descriptor
 * format: "TLV2" then records of [type u8][len u16 LE][value]          */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_FILE 65536
#define MAX_TAGS 8

enum { T_NAME = 1, T_TAG = 2, T_SERIAL = 3, T_END = 0xff };

struct desc {
    char name[64];
    char tags[MAX_TAGS][16];
    int ntags;
    char serial[24];
};

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void copy_field(char *dst, size_t cap, const unsigned char *src, uint16_t len)
{
    size_t n = len;
    if (n > cap - 1)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void handle(struct desc *d, uint8_t type, const unsigned char *p, uint16_t len)
{
    switch (type) {
    case T_NAME:
        copy_field(d->name, sizeof d->name, p, len);
        break;
    case T_TAG:
        if (d->ntags < MAX_TAGS)
            copy_field(d->tags[d->ntags++], sizeof d->tags[0], p, len);
        break;
    case T_SERIAL:
        copy_field(d->serial, sizeof d->serial, p, len);
        break;
    default:
        break;
    }
}

int main(int argc, char **argv)
{
    struct desc d;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <descriptor>\n", argv[0]);
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
    if (n < 4 || memcmp(buf, "TLV2", 4) != 0) {
        fprintf(stderr, "not a descriptor\n");
        free(buf);
        return 1;
    }
    memset(&d, 0, sizeof d);
    size_t off = 4;
    while (off + 3 <= n) {
        uint8_t type = buf[off];
        uint16_t len = rd16(buf + off + 1);
        off += 3;
        if (len > n - off || type == T_END)
            break;
        handle(&d, type, buf + off, len);
        off += len;
    }
    printf("name: %s\nserial: %s\n", d.name, d.serial);
    for (int i = 0; i < d.ntags; i++)
        printf("tag: %s\n", d.tags[i]);
    free(buf);
    return 0;
}
