/* md5.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/* 
 * \file	md5.c
 * \author	Daniel Otte
 * \date 	2006-07-31
 * \license GPLv3 or later
 * \brief   Implementation of the MD5 hash algorithm as described in RFC 1321
 * 
 */

#include "md5.h"
#include <stdint.h>
#include <string.h>
#ifdef __AVR__
	#include <avr/pgmspace.h>
#else
	#define PROGMEM
	#define pgm_read_dword(x) (*(x))
#endif

uint32_t md5_T[] PROGMEM = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
	0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
	0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
	0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
	0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
	0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
	0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
	0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
	0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
	0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

void md5_init(md5_ctx_t *s){
	s->counter = 0;
	s->a[0] = 0x67452301;
	s->a[1] = 0xefcdab89;
	s->a[2] = 0x98badcfe;
	s->a[3] = 0x10325476;
}

static 
uint32_t md5_F(uint32_t x, uint32_t y, uint32_t z){
	return ((x&y)|((~x)&z));
}

static
uint32_t md5_G(uint32_t x, uint32_t y, uint32_t z){
	return ((x&z)|((~z)&y));
}

static
uint32_t md5_H(uint32_t x, uint32_t y, uint32_t z){
	return (x^y^z);
}

static
uint32_t md5_I(uint32_t x, uint32_t y, uint32_t z){
	return (y ^ (x | (~z)));
}

typedef uint32_t md5_func_t(uint32_t, uint32_t, uint32_t);

#define ROTL32(x,n) (((x)<<(n)) | ((x)>>(32-(n))))  

static
void md5_core(uint32_t* a, void* block, uint8_t as, uint8_t s, uint8_t i, uint8_t fi){
	uint32_t t;
	md5_func_t* funcs[]={md5_F, md5_G, md5_H, md5_I};
	as &= 0x3;
	/* a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
	t = a[as] + funcs[fi](a[(as+1)&3], a[(as+2)&3], a[(as+3)&3]) 
	    + *((uint32_t*)block) + pgm_read_dword(md5_T+i) ;
	a[as]=a[(as+1)&3] + ROTL32(t, s);
}

void md5_nextBlock(md5_ctx_t *state, const void* block){
	uint32_t	a[4];
	uint8_t		m,n,i=0;
	/* this requires other mixed sboxes */
	
	a[0]=state->a[0];
	a[1]=state->a[1];
	a[2]=state->a[2];
	a[3]=state->a[3];
	
	/* round 1 */
	uint8_t s1t[]={7,12,17,22}; // 1,-1   1,4   2,-1   3,-2
	for(m=0;m<4;++m){
		for(n=0;n<4;++n){
			md5_core(a, &(((uint32_t*)block)[m*4+n]), 4-n, s1t[n],i++,0);
		}
	}
	/* round 2 */
	uint8_t s2t[]={5,9,14,20}; // 1,-3   1,1   2,-2   2,4
	for(m=0;m<4;++m){
		for(n=0;n<4;++n){
			md5_core(a, &(((uint32_t*)block)[(1+m*4+n*5)&0xf]), 4-n, s2t[n],i++,1);
		}
	}
	/* round 3 */
	uint8_t s3t[]={4,11,16,23}; // 0,4   1,3   2,0   3,-1
	for(m=0;m<4;++m){
		for(n=0;n<4;++n){
			md5_core(a, &(((uint32_t*)block)[(5-m*4+n*3)&0xf]), 4-n, s3t[n],i++,2);
		}
	}
	/* round 4 */
	uint8_t s4t[]={6,10,15,21}; // 1,-2   1,2   2,-1   3,-3
	for(m=0;m<4;++m){
		for(n=0;n<4;++n){
			md5_core(a, &(((uint32_t*)block)[(0-m*4+n*7)&0xf]), 4-n, s4t[n],i++,3);
		}
	}
	state->a[0] += a[0];
	state->a[1] += a[1];
	state->a[2] += a[2];
	state->a[3] += a[3];
	state->counter++;
}

void md5_lastBlock(md5_ctx_t *state, const void* block, uint16_t length_b){
	uint16_t l;
	uint8_t b[64];
	while (length_b >= 512){
		md5_nextBlock(state, block);
		length_b -= 512;
		block = ((uint8_t*)block) + 512/8;
	}
	memset(b, 0, 64);
	memcpy(b, block, length_b/8);
	/* insert padding one */
	l=length_b/8;
	if(length_b%8){
		uint8_t t;
		t = ((uint8_t*)block)[l];
		t |= (0x80>>(length_b%8));
		b[l]=t;
	}else{
		b[l]=0x80;
	}
	/* insert length value */
	if(l+sizeof(uint64_t) >= 512/8){
		md5_nextBlock(state, b);
		state->counter--;
		memset(b, 0, 64-8);
	}
	*((uint64_t*)&b[64-sizeof(uint64_t)]) = (state->counter * 512) + length_b;
	md5_nextBlock(state, b);
}

void md5_ctx2hash(md5_hash_t dest, const md5_ctx_t* state){
	memcpy(dest, state->a, MD5_HASH_BYTES);
}

void md5(md5_hash_t dest, const void* msg, uint32_t length_b){
	md5_ctx_t ctx;
	md5_init(&ctx);
	while(length_b>=MD5_BLOCK_BITS){
		md5_nextBlock(&ctx, msg);
		msg = (uint8_t*)msg + MD5_BLOCK_BYTES;
		length_b -= MD5_BLOCK_BITS;
	}
	md5_lastBlock(&ctx, msg, length_b);
	md5_ctx2hash(dest, &ctx);
}

