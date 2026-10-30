/* evreplay - replay a binary event log
 * format: "EVT1" then records [type u8][len u16 LE][data]            */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

enum { EV_BOOT = 1, EV_LOGIN = 2, EV_LOGOUT = 3, EV_DIAG = 7 };
enum { LOG_DEBUG, LOG_INFO, LOG_WARN };

static int verbosity = LOG_INFO;
static const char *const level_names[] = { "debug", "info", "warn" };

static void log_line(int level, const char *msg)
{
    if (level < verbosity)
        return;
    fprintf(stderr, "[%s] ", level_names[level]);
    fprintf(stderr, msg);
    fputc('\n', stderr);
}

static void copy_text(char *dst, size_t cap, const unsigned char *p, uint16_t len)
{
    size_t n = len < cap - 1 ? len : cap - 1;
    memcpy(dst, p, n);
    dst[n] = '\0';
}

static void replay(const unsigned char *p, uint8_t type, uint16_t len)
{
    char text[256];
    switch (type) {
    case EV_BOOT:
        log_line(LOG_INFO, "system boot");
        break;
    case EV_LOGIN:
        copy_text(text, sizeof text, p, len);
        printf("login: %s\n", text);
        break;
    case EV_LOGOUT:
        log_line(LOG_DEBUG, "logout");
        break;
    case EV_DIAG:
        copy_text(text, sizeof text, p, len);
        log_line(LOG_WARN, text);
        break;
    default:
        log_line(LOG_WARN, "unknown event type");
        break;
    }
}

int main(int argc, char **argv)
{
    static unsigned char buf[16384];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <event.log>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 4 || memcmp(buf, "EVT1", 4) != 0) {
        fprintf(stderr, "not an event log\n");
        return 1;
    }
    size_t off = 4;
    unsigned events = 0;
    while (off + 3 <= n) {
        uint8_t type = buf[off];
        uint16_t len = (uint16_t)(buf[off + 1] | (buf[off + 2] << 8));
        off += 3;
        if (len > n - off)
            break;
        replay(buf + off, type, len);
        off += len;
        events++;
    }
    printf("%u events replayed\n", events);
    return 0;
}
