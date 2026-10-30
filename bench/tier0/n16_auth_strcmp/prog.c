/* login (fixed) - the token must equal the secret exactly (strcmp), so an empty or partial
 * token is rejected. Negative control for the auth-bypass class. */
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
    if (strcmp(token, secret) == 0) {
        printf("LYKOS_AUTH_OK\n");
        return 0;
    }
    printf("denied\n");
    return 1;
}
