
/**
 * `decode.c' - b64
 *
 * copyright (c) 2014 joseph werle
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "b64.h"

#ifdef b64_USE_CUSTOM_MALLOC
extern void* b64_malloc(size_t);
#endif

#ifdef b64_USE_CUSTOM_REALLOC
extern void* b64_realloc(void*, size_t);
#endif

unsigned char*
b64_decode(const char* src, size_t len) {
    return b64_decode_ex(src, len, NULL);
}

unsigned char*
b64_decode_ex(const char* src, size_t len, size_t* decsize) {
    int i = 0;
    int j = 0;
    int l = 0;
    size_t size = 0;
    unsigned char* dec = NULL;
    unsigned char buf[3];
    unsigned char tmp[4];

    
    dec = (unsigned char*)b64_buf_malloc();
    if (NULL == dec) { return NULL; }

    
    while (len--) {
        
        if ('=' == src[j]) { break; }
        if (!(isalnum(src[j]) || '+' == src[j] || '/' == src[j])) { break; }

        
        tmp[i++] = src[j++];

        
        if (4 == i) {
            
            for (i = 0; i < 4; ++i) {
                
                for (l = 0; l < 64; ++l) {
                    if (tmp[i] == b64_table[l]) {
                        tmp[i] = l;
                        break;
                    }
                }
            }

            
            buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
            buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
            buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

            
            dec = (unsigned char*)b64_buf_realloc(dec, size + 3);
            if (dec != NULL) {
                for (i = 0; i < 3; ++i) {
                    dec[size++] = buf[i];
                }
            }
            else {
                return NULL;
            }

            
            i = 0;
        }
    }

    
    if (i > 0) {
        
        for (j = i; j < 4; ++j) {
            tmp[j] = '\0';
        }

        
        for (j = 0; j < 4; ++j) {
            
            for (l = 0; l < 64; ++l) {
                if (tmp[j] == b64_table[l]) {
                    tmp[j] = l;
                    break;
                }
            }
        }

        
        buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
        buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
        buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

        
        dec = (unsigned char*)b64_buf_realloc(dec, size + (i - 1));
        if (dec != NULL) {
            for (j = 0; (j < i - 1); ++j) {
                dec[size++] = buf[j];
            }
        }
        else {
            return NULL;
        }
    }

    
    dec = (unsigned char*)b64_buf_realloc(dec, size + 1);
    if (dec != NULL) {
        dec[size] = '\0';
    }
    else {
        return NULL;
    }

    
    if (decsize != NULL) {
        *decsize = size;
    }

    return dec;
}