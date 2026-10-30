/* fwapply - validate and apply a firmware update package
 * format: "FWUP" version(u8 == 2) len(u16 LE) payload[len] csum(u8)
 *         the byte-sum of payload plus csum must be 0 (mod 256)
 * payload: name_len(u8) name[name_len] image[...]                    */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int checksum_ok(const unsigned char *p, uint16_t len, uint8_t csum)
{
    uint8_t sum = csum;
    for (uint16_t i = 0; i < len; i++)
        sum = (uint8_t)(sum + p[i]);
    return sum == 0;
}

static int apply_update(const unsigned char *p, uint16_t len)
{
    char section[32];
    uint8_t name_len = p[0];
    if (len < 1 || name_len > len - 1)
        return -1;
    memcpy(section, p + 1, name_len);
    section[name_len < sizeof section ? name_len : sizeof section - 1] = '\0';
    printf("flashing section '%s' with %u image bytes\n", section, (unsigned)(len - 1 - name_len));
    return 0;
}

int main(int argc, char **argv)
{
    static unsigned char buf[8192];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <package>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 8 || memcmp(buf, "FWUP", 4) != 0 || buf[4] != 2) {
        fprintf(stderr, "not a v2 package\n");
        return 1;
    }
    uint16_t len = (uint16_t)(buf[5] | (buf[6] << 8));
    if (len == 0 || (size_t)len + 8 > n) {
        fprintf(stderr, "bad length\n");
        return 1;
    }
    if (!checksum_ok(buf + 7, len, buf[7 + len])) {
        fprintf(stderr, "checksum mismatch\n");
        return 1;
    }
    if (apply_update(buf + 7, len) != 0) {
        fprintf(stderr, "malformed payload\n");
        return 1;
    }
    return 0;
}
