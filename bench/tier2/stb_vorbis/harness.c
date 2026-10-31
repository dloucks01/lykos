/* tier-2 harness: decode an Ogg/Vorbis file from memory the way an app would. A malformed stream
 * that makes stb_vorbis read/write out of bounds is the bug; ASan is the oracle. stb_vorbis has a
 * documented cluster of fuzz-found invalid-file crash fixes (2015-09..2018-01); the differential
 * (crashes vuln, survives fixed) is the ground truth. */
#include "target.h"   /* scorer symlinks this to vuln.h or fixed.h (stb_vorbis.c, impl by default) */
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
    int ch=0, rate=0; short *out=NULL;
    int samples=stb_vorbis_decode_memory(buf,(int)n,&ch,&rate,&out);
    (void)samples;
    if(out) free(out);
    free(buf);
    return 0;
}
