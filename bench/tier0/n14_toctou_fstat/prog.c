/* catsmall (fixed) - open the file first, then fstat the OPEN descriptor, so the object that
 * was checked is exactly the object that is read. Swapping the path afterwards cannot change the
 * already-open fd, so there is no check-to-use race. Negative control for TOCTOU. */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size > 4096) {
        fprintf(stderr, "file too big or stat failed\n");
        fclose(f);
        return 1;
    }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}
