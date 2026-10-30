/* cfgread - open an include file under the config directory and copy it to stdout.
 * The include name is appended to the relative base "conf.d/" and opened via openat() with
 * no check for `..`, so ../../../../etc/passwd escapes the config directory. */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char path[256];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <include>\n", argv[0]);
        return 2;
    }
    strcpy(path, "conf.d/");
    strncat(path, argv[1], sizeof(path) - strlen(path) - 1);   /* include not sanitised */
    int fd = openat(AT_FDCWD, path, O_RDONLY);                 /* CWE-22 site */
    if (fd < 0) {
        perror(path);
        return 1;
    }
    char buf[512];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0)
        write(1, buf, n);
    close(fd);
    return 0;
}
