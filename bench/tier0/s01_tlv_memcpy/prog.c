/* tlvdump - print the fields of a TLV-encoded device descriptor
 * format: "TLV1" then records of [type u8][len u16 LE][value]          */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_FILE 65536

enum { T_NAME = 1, T_VERSION = 2, T_SERIAL = 3, T_END = 0xff };

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void handle_name(const unsigned char *p, uint16_t len)
{
    char name[64];
    memcpy(name, p, len);
    printf("name:    %.*s\n", (int)len, name);
}

static void handle_version(const unsigned char *p, uint16_t len)
{
    if (len != 2) {
        fprintf(stderr, "bad version record\n");
        return;
    }
    printf("version: %u.%u\n", p[0], p[1]);
}

static void handle_serial(const unsigned char *p, uint16_t len)
{
    char serial[24];
    if (len >= sizeof serial)
        len = sizeof serial - 1;
    memcpy(serial, p, len);
    serial[len] = '\0';
    printf("serial:  %s\n", serial);
}

int main(int argc, char **argv)
{
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
    if (n < 4 || memcmp(buf, "TLV1", 4) != 0) {
        fprintf(stderr, "not a descriptor\n");
        free(buf);
        return 1;
    }
    size_t off = 4;
    while (off + 3 <= n) {
        uint8_t type = buf[off];
        uint16_t len = rd16(buf + off + 1);
        off += 3;
        if (len > n - off) {
            fprintf(stderr, "truncated record\n");
            break;
        }
        if (type == T_END)
            break;
        switch (type) {
        case T_NAME:    handle_name(buf + off, len); break;
        case T_VERSION: handle_version(buf + off, len); break;
        case T_SERIAL:  handle_serial(buf + off, len); break;
        default:        fprintf(stderr, "skipping type %u\n", type); break;
        }
        off += len;
    }
    free(buf);
    return 0;
}
