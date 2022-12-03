
/**
 * `encode.c' - b64
 *
 * copyright (c) 2014 joseph werle
 */

#include <stdio.h>
#include <stdlib.h>
#include "b64.h"

#ifdef b64_USE_CUSTOM_MALLOC
extern void* b64_malloc(size_t);
#endif

#ifdef b64_USE_CUSTOM_REALLOC
extern void* b64_realloc(void*, size_t);
#endif

char*
b64_encode(const unsigned char* src, size_t len) {
    int i = 0;
    int j = 0;
    char* enc = NULL;
    size_t size = 0;
    unsigned char buf[4];
    unsigned char tmp[3];

    
    enc = (char*)b64_buf_malloc();
    if (NULL == enc) { return NULL; }

    
    while (len--) {
        
        tmp[i++] = *(src++);

        
        if (3 == i) {
            buf[0] = (tmp[0] & 0xfc) >> 2;
            buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
            buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
            buf[3] = tmp[2] & 0x3f;

            enc = (char*)b64_buf_realloc(enc, size + 4);
            for (i = 0; i < 4; ++i) {
                enc[size++] = b64_table[buf[i]];
            }

            
            i = 0;
        }
    }

    
    if (i > 0) {
        
        for (j = i; j < 3; ++j) {
            tmp[j] = '\0';
        }

        
        buf[0] = (tmp[0] & 0xfc) >> 2;
        buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
        buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
        buf[3] = tmp[2] & 0x3f;

        
        for (j = 0; (j < i + 1); ++j) {
            enc = (char*)b64_buf_realloc(enc, size + 1);
            enc[size++] = b64_table[buf[j]];
        }


        while ((i++ < 3)) {
            enc = (char*)b64_buf_realloc(enc, size + 1);
            enc[size++] = '=';
        }
    }

    
    enc = (char*)b64_buf_realloc(enc, size + 1);
    enc[size] = '\0';

    return enc;
}