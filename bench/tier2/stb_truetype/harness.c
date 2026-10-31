/* tier-2 harness: parse a font and rasterize a glyph the way an app would. A malformed font that
 * makes stb_truetype read/write out of bounds is the bug; ASan is the oracle. The vuln version
 * predates the 2018 stbtt_hheap "severe badness" fix (and later invalid-font fixes); the
 * differential (crashes vuln, survives fixed) is the ground truth. */
#define STB_TRUETYPE_IMPLEMENTATION
#include "target.h"   /* scorer symlinks this to vuln.h or fixed.h */
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
    stbtt_fontinfo font;
    if(stbtt_InitFont(&font, buf, stbtt_GetFontOffsetForIndex(buf,0))){
        float sc = stbtt_ScaleForPixelHeight(&font, 48.0f);
        /* rasterize a handful of glyphs -- the OOB bugs live in glyph shape/bitmap paths */
        for(int cp=0x20; cp<0x30; cp++){
            int w=0,h=0,xo=0,yo=0;
            unsigned char *bmp=stbtt_GetCodepointBitmap(&font, 0, sc, cp, &w, &h, &xo, &yo);
            if(bmp) free(bmp);
        }
    }
    free(buf);
    return 0;
}
