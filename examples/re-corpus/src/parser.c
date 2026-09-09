#include <stdio.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv){
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb"); if(!f) return 0;
    unsigned char hdr[4];
    if (fread(hdr,1,4,f)!=4){fclose(f);return 0;}
    if (memcmp(hdr,"LYK\0",4)!=0){fclose(f);return 1;}
    uint32_t len; if(fread(&len,1,4,f)!=4){fclose(f);return 0;}
    char buf[64]; unsigned char tmp[8192];
    uint32_t n = len>8192?8192:len;
    size_t got = fread(tmp,1,n,f);
    memcpy(buf,tmp,got);
    fclose(f); return buf[0];
}
