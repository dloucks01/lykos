/* loginbox (fixed) - a bounded read, so no overflow and no way to reach win. Negative control. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void win(void)
{
    puts("LYKOS_PWNED");
    fflush(stdout);
    _exit(0);
}

void greet(void)
{
    char name[64];
    ssize_t n = read(0, name, sizeof name - 1);   /* bounded: no overflow */
    if (n < 0)
        return;
    name[n] = 0;
    printf("hi %s\n", name);
}

int main(void)
{
    greet();
    return 0;
}
