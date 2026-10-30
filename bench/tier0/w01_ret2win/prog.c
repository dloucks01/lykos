/* loginbox - read a line into a fixed buffer with an over-long read, then echo it. The read
 * overflows `name` and the saved return address (stack overflow -> RIP control). win() is never
 * reached on any normal path; it is the attacker-chosen ret2win target. */
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
    ssize_t n = read(0, name, 512);   /* CWE-121: reads up to 512 bytes into name[64] */
    if (n < 0)
        return;
    printf("hi %s\n", name);
}

int main(void)
{
    greet();
    return 0;
}
