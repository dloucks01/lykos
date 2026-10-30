/* netwatch - check reachability of the hosts listed in a watch file, one "host <name>" per line */
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(const char *host)
{
    char cmd[300];
    snprintf(cmd, sizeof cmd, "ping -c 1 -W 1 %s >/dev/null 2>&1", host);
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("%s: %s\n", host, (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? "up" : "down");
}

int main(int argc, char **argv)
{
    char line[256];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <watchfile>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "host ", 5) == 0 && line[5] != '\0')
            check(line + 5);
    }
    fclose(f);
    return 0;
}
