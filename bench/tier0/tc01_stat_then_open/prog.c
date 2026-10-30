/* catsmall - print a file, but only if it is small. The size is checked with stat(), then
 * (after a short logging/work window) the path is opened AGAIN with fopen(). A symlink swapped
 * in during the window lets a file the check rejected be read anyway: a check-to-use race
 * (CWE-367, TOCTOU). */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    struct stat st;
    if (stat(argv[1], &st) != 0) {       /* CHECK */
        perror("stat");
        return 1;
    }
    if (st.st_size > 4096) {
        fprintf(stderr, "file too big\n");
        return 1;
    }
    fprintf(stderr, "serving %s (%ld bytes)\n", argv[1], (long)st.st_size);
    usleep(2000);                        /* check-to-use window */
    FILE *f = fopen(argv[1], "rb");      /* USE: path re-resolved here (CWE-367 site) */
    if (!f) {
        perror("open");
        return 1;
    }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}
