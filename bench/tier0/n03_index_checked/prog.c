/* regload2 - apply a register preset and a reading batch
 * format: "REG2" nents(u8) nents x [slot s8][value u32 LE]
 *         count(u8) count x reading(u16 LE)                           */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NREGS 16
#define MAX_READINGS 16

static uint32_t regs[NREGS];

static void set_reg(int slot, uint32_t value)
{
    if (slot >= 0 && slot < NREGS)
        regs[slot] = value;
}

static uint32_t read_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv)
{
    static unsigned char buf[4096];
    uint16_t readings[MAX_READINGS];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <preset>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 5 || memcmp(buf, "REG2", 4) != 0) {
        fprintf(stderr, "not a preset\n");
        return 1;
    }
    size_t off = 5;
    unsigned nents = buf[4];
    for (unsigned i = 0; i < nents && off + 5 <= n; i++, off += 5)
        set_reg((int8_t)buf[off], read_u32(buf + off + 1));
    unsigned count = off < n ? buf[off++] : 0;
    unsigned got = 0;
    for (unsigned i = 0; i < count && i < MAX_READINGS && off + 2 <= n; i++, off += 2)
        readings[got++] = (uint16_t)(buf[off] | (buf[off + 1] << 8));
    uint32_t sum = 0;
    for (unsigned i = 0; i < got; i++)
        sum += readings[i];
    for (int i = 0; i < NREGS; i++)
        printf("r%-2d = 0x%08x\n", i, regs[i]);
    printf("%u readings, sum %u\n", got, sum);
    return 0;
}
