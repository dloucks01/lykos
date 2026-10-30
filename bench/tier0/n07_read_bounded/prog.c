/* rpcd2 - handle one framed RPC request on stdin
 * header: 'R' 'P' version(1) opcode(1) length(u32 LE), then body     */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

enum { OP_PING = 0, OP_ECHO = 1 };

static int read_full(int fd, void *dst, size_t n)
{
    unsigned char *p = dst;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0)
            return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static int handle_echo(uint32_t len)
{
    char body[128];
    if (len > sizeof body) {
        fprintf(stderr, "body too large\n");
        return -1;
    }
    ssize_t r = read(STDIN_FILENO, body, len);
    if (r < 0)
        return -1;
    printf("ECHO %zd ", r);
    fwrite(body, 1, (size_t)r, stdout);
    putchar('\n');
    return 0;
}

int main(void)
{
    unsigned char hdr[8];
    if (read_full(STDIN_FILENO, hdr, sizeof hdr) != 0 ||
        hdr[0] != 'R' || hdr[1] != 'P' || hdr[2] != 1) {
        fprintf(stderr, "bad header\n");
        return 1;
    }
    uint32_t len = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
                   ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
    if (hdr[3] == OP_PING) {
        puts("PONG");
        return 0;
    }
    if (hdr[3] == OP_ECHO)
        return handle_echo(len) == 0 ? 0 : 1;
    fprintf(stderr, "unknown opcode\n");
    return 1;
}
