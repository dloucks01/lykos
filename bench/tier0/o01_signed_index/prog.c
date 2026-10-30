/* regload - apply a register preset file and print the resulting state
 * format: "REGS" then 5-byte entries [slot s8][value u32 LE]           */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NREGS 16

static void set_reg(uint32_t *regs, int slot, uint32_t value)
{
    if (slot < NREGS)
        regs[slot] = value;
}

static int apply_preset(FILE *f, uint32_t *regs)
{
    unsigned char e[5];
    int applied = 0;
    while (fread(e, 1, sizeof e, f) == sizeof e) {
        int slot = (int8_t)e[0];
        uint32_t v = (uint32_t)e[1] | ((uint32_t)e[2] << 8) |
                     ((uint32_t)e[3] << 16) | ((uint32_t)e[4] << 24);
        set_reg(regs, slot, v);
        applied++;
    }
    return applied;
}

int main(int argc, char **argv)
{
    uint32_t regs[NREGS];
    char magic[4];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <preset>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("open");
        return 1;
    }
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "REGS", 4) != 0) {
        fprintf(stderr, "not a preset\n");
        fclose(f);
        return 1;
    }
    memset(regs, 0, sizeof regs);
    int n = apply_preset(f, regs);
    fclose(f);
    printf("%d entries applied\n", n);
    for (int i = 0; i < NREGS; i++)
        printf("r%-2d = 0x%08x\n", i, regs[i]);
    return 0;
}
