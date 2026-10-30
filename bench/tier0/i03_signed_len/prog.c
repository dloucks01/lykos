/* labelrec - read label records from stdin and print them
 * record: [type u8][flags u8][rec_len u16 LE (includes the 4-byte header)][payload] */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define LABEL_MAX 64

static int handle_record(const unsigned char *rec, unsigned rec_len)
{
    char label[LABEL_MAX];
    int len = (int)rec_len - 4;
    if (len < LABEL_MAX) {
        memcpy(label, rec + 4, len);
        label[len] = '\0';
    } else {
        memcpy(label, rec + 4, LABEL_MAX - 1);
        label[LABEL_MAX - 1] = '\0';
    }
    printf("type %u flags %02x label '%s'\n", rec[0], rec[1], label);
    return 0;
}

int main(void)
{
    static unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    size_t off = 0;
    int count = 0;
    while (off + 4 <= n) {
        unsigned rec_len = (unsigned)buf[off + 2] | ((unsigned)buf[off + 3] << 8);
        if (rec_len == 0 || rec_len > n - off)
            break;
        handle_record(buf + off, rec_len);
        off += rec_len;
        count++;
    }
    printf("%d records\n", count);
    return 0;
}
