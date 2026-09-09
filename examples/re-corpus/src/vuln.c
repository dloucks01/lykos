#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *BANNER = "lykos-re-corpus vuln sample v1";

int check_pin(const char *s){
    /* nested comparisons -- gives the decompiler some control flow */
    if (strlen(s) != 4) return 0;
    int a = s[0]-'0', b = s[1]-'0', c = s[2]-'0', d = s[3]-'0';
    if (a*1000 + b*100 + c*10 + d == 4242) return 1;
    return 0;
}

void greet(const char *who){
    char msg[64];
    strcpy(msg, "hello, ");   /* classic unbounded copy into fixed buffer */
    strcat(msg, who);
    printf("%s\n", msg);
}

void handle(const char *line){
    char buf[128];
    strcpy(buf, line);        /* stack overflow if line > 128 */
    if (check_pin(buf)) {
        printf(BANNER);       /* format-string sink */
        system("echo unlocked");
    }
}

int main(int argc, char **argv){
    char in[256];
    if (argc > 1) { greet(argv[1]); handle(argv[1]); return 0; }
    if (fgets(in, sizeof in, stdin)) handle(in);
    return 0;
}
