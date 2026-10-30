/* capreplay - replay a capture file of [tag u8][len u8][data] records
 * tags: 'K' unlock key (4 bytes), 'M' mode (1 byte), 'D' data       */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

enum { MODE_TEXT = 0, MODE_HEX = 1, MODE_RAW = 2 };

static int unlocked;
static int mode = MODE_TEXT;

static void on_key(const unsigned char *p, uint8_t len)
{
    static const unsigned char service_key[4] = { 0xc0, 0xde, 0xf0, 0x0d };
    unlocked = (len == 4 && memcmp(p, service_key, 4) == 0);
}

static void on_mode(const unsigned char *p, uint8_t len)
{
    if (len != 1 || p[0] > MODE_RAW)
        return;
    if (p[0] == MODE_RAW && !unlocked)
        return;
    mode = p[0];
}

static void on_data(const unsigned char *p, uint8_t len)
{
    char line[48];
    if (mode == MODE_RAW) {
        memcpy(line, p, len);
        fwrite(line, 1, len, stdout);
        putchar('\n');
        return;
    }
    size_t n = len < sizeof line - 1 ? len : sizeof line - 1;
    memcpy(line, p, n);
    line[n] = '\0';
    if (mode == MODE_HEX) {
        for (size_t i = 0; i < n; i++)
            printf("%02x", (unsigned char)line[i]);
        putchar('\n');
    } else {
        printf("%s\n", line);
    }
}

int main(int argc, char **argv)
{
    static unsigned char buf[4096];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <capture>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    size_t off = 0;
    while (off + 2 <= n) {
        uint8_t tag = buf[off], len = buf[off + 1];
        off += 2;
        if (len > n - off)
            break;
        switch (tag) {
        case 'K': on_key(buf + off, len); break;
        case 'M': on_mode(buf + off, len); break;
        case 'D': on_data(buf + off, len); break;
        default: break;
        }
        off += len;
    }
    return 0;
}
