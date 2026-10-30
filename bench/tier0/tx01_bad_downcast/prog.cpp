/* shapes - build a shape from a record, then act on it. The code trusts a separate "kind" byte
 * (buf[1]) to decide the downcast instead of the real object type, so a Circle can be cast to
 * Square and its vtable used as the wrong type: a type confusion (CWE-843). UBSan's vptr check
 * flags the bad downcast. */
#include <cstdio>

struct Shape { virtual ~Shape() {} virtual int area() const { return 0; } };
struct Circle : Shape { int r; int area() const override { return 3 * r * r; } };
struct Square : Shape { int s; int area() const override { return s * s; } };

int main(int argc, char **argv)
{
    unsigned char buf[16];
    if (argc < 2)
        return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 8)
        return 1;
    Shape *s = (buf[0] == 'C') ? (Shape *)new Circle() : (Shape *)new Square();
    if (buf[1] == 'S') {
        Square *sq = static_cast<Square *>(s);   /* CWE-843: s may really be a Circle */
        sq->s = buf[2];
        printf("sq area %d\n", sq->area());
    } else {
        printf("shape area %d\n", s->area());
    }
    delete s;
    return 0;
}
