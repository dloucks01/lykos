/* kvhash - read "BUCKETS <n>" then "PUT <key>" lines on stdin and report bucket placement */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned hash(const char *s)
{
    unsigned h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h;
}

int main(void)
{
    char line[256];
    int buckets = 16;
    unsigned counts[64] = {0};
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "BUCKETS ", 8) == 0) {
            int b = atoi(line + 8);
            if (b < 0 || b > 64) {
                fprintf(stderr, "too many buckets\n");
                return 1;
            }
            buckets = b;
        } else if (strncmp(line, "PUT ", 4) == 0) {
            unsigned slot = hash(line + 4) % (unsigned)buckets;
            counts[slot]++;
            printf("%s -> bucket %u\n", line + 4, slot);
        }
    }
    return 0;
}
