/* mqload - load a message-queue spool file and print queued messages
 * format: "MQ" then records of [prio u8][len u16 LE][body]            */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BODY_MAX 128
#define MAX_MSGS 32

struct message {
    uint8_t prio;
    uint16_t len;
    unsigned char *body;
};

static struct message *msg_new(uint8_t prio, const unsigned char *src, uint16_t len)
{
    struct message *m = malloc(sizeof *m);
    if (!m)
        return NULL;
    m->prio = prio;
    m->len = len;
    m->body = malloc(BODY_MAX);
    memcpy(m->body, src, len);
    return m;
}

static void msg_free(struct message *m)
{
    free(m->body);
    free(m);
}

int main(int argc, char **argv)
{
    static unsigned char buf[65536];
    struct message *q[MAX_MSGS];
    int count = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <spool>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 2 || buf[0] != 'M' || buf[1] != 'Q') {
        fprintf(stderr, "not a spool file\n");
        return 1;
    }
    size_t off = 2;
    while (off + 3 <= n && count < MAX_MSGS) {
        uint8_t prio = buf[off];
        uint16_t len = (uint16_t)(buf[off + 1] | (buf[off + 2] << 8));
        off += 3;
        if (len > n - off)
            break;
        struct message *m = msg_new(prio, buf + off, len);
        if (!m)
            break;
        q[count++] = m;
        off += len;
    }
    for (int i = 0; i < count; i++) {
        printf("[%u] %.*s\n", q[i]->prio, (int)q[i]->len, (const char *)q[i]->body);
        msg_free(q[i]);
    }
    return 0;
}
