/* httpline - parse an HTTP/1.x request head from stdin and route it */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct request {
    char method[16];
    char path[256];
    int minor;
};

static int parse_request_line(const char *line, struct request *req)
{
    char method[16];
    size_t i;
    for (i = 0;; i++) {
        char c = line[i];
        if (c == ' ' || c == '\0' || c == '\r' || c == '\n')
            c = '\0';
        method[i] = c;
        if (c == '\0')
            break;
    }
    if (line[i] != ' ')
        return -1;
    const char *path = line + i + 1;
    const char *sp = strchr(path, ' ');
    if (!sp || (size_t)(sp - path) >= sizeof req->path)
        return -1;
    memcpy(req->path, path, (size_t)(sp - path));
    req->path[sp - path] = '\0';
    if (strncmp(sp + 1, "HTTP/1.", 7) != 0)
        return -1;
    req->minor = sp[8] == '1' ? 1 : 0;
    memcpy(req->method, method, sizeof req->method);
    return 0;
}

int main(void)
{
    char line[1024];
    struct request req;
    int headers = 0;
    if (!fgets(line, sizeof line, stdin)) {
        fprintf(stderr, "empty request\n");
        return 1;
    }
    if (parse_request_line(line, &req) != 0) {
        puts("HTTP/1.0 400 Bad Request");
        return 0;
    }
    while (fgets(line, sizeof line, stdin)) {
        if (line[0] == '\r' || line[0] == '\n')
            break;
        headers++;
    }
    if (strcmp(req.method, "GET") == 0 || strcmp(req.method, "HEAD") == 0)
        printf("HTTP/1.%d 200 OK (%s, %d headers)\n", req.minor, req.path, headers);
    else
        printf("HTTP/1.%d 405 Method Not Allowed\n", req.minor);
    return 0;
}
