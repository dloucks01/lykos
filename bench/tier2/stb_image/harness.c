/* tier-2 harness: decode an image file the way an app would. A malformed file that makes
 * stb_image read/write out of bounds is the bug; ASan is the oracle. */
#define STB_IMAGE_IMPLEMENTATION
#include "target.h"   /* scorer symlinks this to vuln.h or fixed.h */           /* symlinked to vuln.h or fixed.h at build time */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv){
    if(argc<2) return 2;
    FILE *f=fopen(argv[1],"rb"); if(!f) return 1;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    if(n<=0||n>(1<<24)){fclose(f);return 1;}
    unsigned char *buf=malloc(n); if(!buf){fclose(f);return 1;}
    if(fread(buf,1,n,f)!=(size_t)n){free(buf);fclose(f);return 1;}
    fclose(f);
    int x,y,c; unsigned char *img=stbi_load_from_memory(buf,(int)n,&x,&y,&c,0);
    if(img) stbi_image_free(img);
    free(buf);
    return 0;
}
