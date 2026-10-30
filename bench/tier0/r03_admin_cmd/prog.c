/* motdd - message-of-the-day daemon speaking a line protocol on stdin
 *   HELO <name> | MOTD | AUTH <pin> | ADMIN SETMOTD <text> | QUIT     */
#include <stdio.h>
#include <string.h>

static char motd[64] = "welcome";
static char peer[32] = "anonymous";
static int authed;

static void admin(char *args)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");
    if (!sub) {
        puts("ERR admin needs a subcommand");
        return;
    }
    if (strcmp(sub, "SETMOTD") == 0 && rest) {
        strcpy(motd, rest);
        puts("OK motd updated");
    } else if (strcmp(sub, "WHO") == 0) {
        printf("OK peer=%s\n", peer);
    } else {
        puts("ERR unknown admin command");
    }
}

int main(void)
{
    char line[512];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *cmd = strtok(line, " ");
        char *arg = strtok(NULL, "");
        if (!cmd)
            continue;
        if (strcmp(cmd, "HELO") == 0 && arg) {
            snprintf(peer, sizeof peer, "%s", arg);
            printf("OK hello %s\n", peer);
        } else if (strcmp(cmd, "MOTD") == 0) {
            printf("OK %s\n", motd);
        } else if (strcmp(cmd, "AUTH") == 0 && arg) {
            authed = strcmp(arg, "7731") == 0;
            puts(authed ? "OK" : "ERR bad pin");
        } else if (strcmp(cmd, "ADMIN") == 0) {
            if (!authed || !arg)
                puts("ERR not authorized");
            else
                admin(arg);
        } else if (strcmp(cmd, "QUIT") == 0) {
            break;
        } else {
            puts("ERR unknown command");
        }
    }
    return 0;
}
