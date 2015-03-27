
/*
 Copyright (c) 2014 Malte Hildingsson, malte (at) afterwi.se
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

#ifndef AW_BASE64_H
#define AW_BASE64_H

#include <stddef.h>
#ifdef __AVR__
    #include <avr/pgmspace.h>
#else
    #define PROGMEM
#endif

#ifdef __cplusplus
extern "C" {
#endif
    
    static inline size_t base64len(size_t n) {
        return (n + 2) / 3 * 4;
    }
    
    static size_t base64(char *buf, size_t nbuf, const unsigned char *p, size_t n) {
        const char t[64] PROGMEM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t i, m = base64len(n);
        unsigned x;
        
        if (nbuf >= m)
            for (i = 0; i < n; ++i) {
                x = p[i] << 0x10;
                x |= (++i < n ? p[i] : 0) << 0x08;
                x |= (++i < n ? p[i] : 0) << 0x00;
                
                *buf++ = t[x >> 3 * 6 & 0x3f];
                *buf++ = t[x >> 2 * 6 & 0x3f];
                *buf++ = (((n - 0 - i) >> 31) & '=') |
                (~((n - 0 - i) >> 31) & t[x >> 1 * 6 & 0x3f]);
                *buf++ = (((n - 1 - i) >> 31) & '=') |
                (~((n - 1 - i) >> 31) & t[x >> 0 * 6 & 0x3f]);
            }
        
        return m;
    }
    
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AW_BASE64_H */

