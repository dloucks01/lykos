/* sensavg - read one sensor batch from stdin and print min/avg/max
 * batch: 'S' 'B' sensor_id(u8) count(u8) then count x u16 LE readings */
#include <stdio.h>
#include <stdint.h>

#define MAX_READINGS 16

static int get_u16(uint16_t *out)
{
    int lo = getchar(), hi = getchar();
    if (lo == EOF || hi == EOF)
        return -1;
    *out = (uint16_t)(lo | (hi << 8));
    return 0;
}

static int read_batch(uint16_t *minv, uint16_t *maxv, uint32_t *avg)
{
    uint16_t readings[MAX_READINGS];
    int count = getchar();
    int n = 0;
    if (count == EOF || count == 0)
        return -1;
    for (int i = 0; i < count; i++) {
        uint16_t v;
        if (get_u16(&v) != 0)
            break;
        readings[i] = v;
        n++;
    }
    if (n == 0)
        return -1;
    uint32_t sum = 0;
    *minv = 0xffff;
    *maxv = 0;
    for (int i = 0; i < n && i < MAX_READINGS; i++) {
        sum += readings[i];
        if (readings[i] < *minv) *minv = readings[i];
        if (readings[i] > *maxv) *maxv = readings[i];
    }
    *avg = sum / (uint32_t)n;
    return n;
}

int main(void)
{
    uint16_t lo, hi;
    uint32_t avg;
    if (getchar() != 'S' || getchar() != 'B') {
        fprintf(stderr, "bad batch magic\n");
        return 1;
    }
    int sensor = getchar();
    if (sensor == EOF)
        return 1;
    int n = read_batch(&lo, &hi, &avg);
    if (n < 0) {
        fprintf(stderr, "empty batch\n");
        return 1;
    }
    printf("sensor %d: n=%d min=%u avg=%u max=%u\n", sensor, n, lo, avg, hi);
    return 0;
}
