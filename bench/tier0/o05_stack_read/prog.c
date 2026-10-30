/* b64d - decode base64 from stdin, print the decoded length and a hex preview */
#include <stdio.h>
#include <string.h>

static const char ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void build_reverse(signed char rev[128])
{
    memset(rev, -1, 128);
    for (int i = 0; i < 64; i++)
        rev[(unsigned char)ALPHA[i]] = (signed char)i;
}

static size_t decode(const unsigned char *in, size_t n, unsigned char *out)
{
    signed char rev[128];
    unsigned acc = 0;
    int bits = 0;
    size_t o = 0;
    build_reverse(rev);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (c == '=' || c == '\n' || c == '\r')
            continue;
        int v = rev[c];
        if (v < 0)
            continue;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    return o;
}

int main(void)
{
    static unsigned char in[8192], out[8192];
    size_t n = fread(in, 1, sizeof in, stdin);
    size_t m = decode(in, n, out);
    printf("decoded %zu bytes:", m);
    for (size_t i = 0; i < m && i < 16; i++)
        printf(" %02x", out[i]);
    putchar('\n');
    return 0;
}
