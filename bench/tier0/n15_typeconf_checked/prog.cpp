/* shapes (fixed) - the downcast is performed only when the record's own kind byte created a
 * Square, so the static type always matches the dynamic type. Negative control for type
 * confusion. */
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
    char kind = buf[0];
    Shape *s = (kind == 'C') ? (Shape *)new Circle() : (Shape *)new Square();
    if (kind == 'S') {
        Square *sq = static_cast<Square *>(s);   /* kind=='S' -> s really is a Square */
        sq->s = buf[2];
        printf("sq area %d\n", sq->area());
    } else {
        printf("shape area %d\n", s->area());
    }
    delete s;
    return 0;
}
