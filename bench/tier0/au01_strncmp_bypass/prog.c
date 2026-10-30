/* login - grant access when the token matches the configured secret (from $LYKOS_SECRET).
 * BUG: strncmp is given strlen(token) as the length, so an EMPTY token compares zero bytes and
 * matches any secret -- an authentication bypass (CWE-287). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    char token[128];
    const char *secret = getenv("LYKOS_SECRET");
    if (!secret)
        secret = "s3cr3t-default";
    if (!fgets(token, sizeof token, stdin))
        return 2;
    token[strcspn(token, "\r\n")] = 0;
    if (strncmp(token, secret, strlen(token)) == 0) {   /* BUG: attacker-chosen length */
        printf("LYKOS_AUTH_OK\n");
        return 0;
    }
    printf("denied\n");
    return 1;
}
