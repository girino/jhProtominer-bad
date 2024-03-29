/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if 1
#define UNROLL_LOOPS /* Enable loops unrolling */
#endif

#include <string.h>
#include <stdio.h>

#include "mysha2.h"

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define my_sha256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define my_sha256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define my_sha256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define my_sha256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x,  1) ^ ROTR(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x,  6))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}

#define UNPACK64(x, str)                      \
{                                             \
    *((str) + 7) = (uint8) ((x)      );       \
    *((str) + 6) = (uint8) ((x) >>  8);       \
    *((str) + 5) = (uint8) ((x) >> 16);       \
    *((str) + 4) = (uint8) ((x) >> 24);       \
    *((str) + 3) = (uint8) ((x) >> 32);       \
    *((str) + 2) = (uint8) ((x) >> 40);       \
    *((str) + 1) = (uint8) ((x) >> 48);       \
    *((str) + 0) = (uint8) ((x) >> 56);       \
}

#define PACK64(str, x)                        \
{                                             \
    *(x) =   ((uint64) *((str) + 7)      )    \
           | ((uint64) *((str) + 6) <<  8)    \
           | ((uint64) *((str) + 5) << 16)    \
           | ((uint64) *((str) + 4) << 24)    \
           | ((uint64) *((str) + 3) << 32)    \
           | ((uint64) *((str) + 2) << 40)    \
           | ((uint64) *((str) + 1) << 48)    \
           | ((uint64) *((str) + 0) << 56);   \
}

/* Macros used for loops unrolling */

#define my_sha256_SCR(i)                         \
{                                             \
    w[i] =  my_sha256_F4(w[i -  2]) + w[i -  7]  \
          + my_sha256_F3(w[i - 15]) + w[i - 16]; \
}

#define SHA512_SCR(i)                         \
{                                             \
    w[i] =  SHA512_F4(w[i -  2]) + w[i -  7]  \
          + SHA512_F3(w[i - 15]) + w[i - 16]; \
}

#define my_sha256_EXP(a, b, c, d, e, f, g, h, j)               \
{                                                           \
    t1 = wv[h] + my_sha256_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + my_sha256_k[j] + w[j];                              \
    t2 = my_sha256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

#define SHA512_EXP(a, b, c, d, e, f, g ,h, j)               \
{                                                           \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + sha512_k[j] + w[j];                              \
    t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

uint32 my_sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
uint32 my_sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
/* SHA-256 functions */

void my_sha256_transf(my_sha256_ctx *ctx, const unsigned char *message,
                   unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;

#ifndef UNROLL_LOOPS
    int j;
#endif

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

#ifndef UNROLL_LOOPS
        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            my_sha256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + my_sha256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + my_sha256_k[j] + w[j];
            t2 = my_sha256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
#else
        PACK32(&sub_block[ 0], &w[ 0]); PACK32(&sub_block[ 4], &w[ 1]);
        PACK32(&sub_block[ 8], &w[ 2]); PACK32(&sub_block[12], &w[ 3]);
        PACK32(&sub_block[16], &w[ 4]); PACK32(&sub_block[20], &w[ 5]);
        PACK32(&sub_block[24], &w[ 6]); PACK32(&sub_block[28], &w[ 7]);
        PACK32(&sub_block[32], &w[ 8]); PACK32(&sub_block[36], &w[ 9]);
        PACK32(&sub_block[40], &w[10]); PACK32(&sub_block[44], &w[11]);
        PACK32(&sub_block[48], &w[12]); PACK32(&sub_block[52], &w[13]);
        PACK32(&sub_block[56], &w[14]); PACK32(&sub_block[60], &w[15]);

        my_sha256_SCR(16); my_sha256_SCR(17); my_sha256_SCR(18); my_sha256_SCR(19);
        my_sha256_SCR(20); my_sha256_SCR(21); my_sha256_SCR(22); my_sha256_SCR(23);
        my_sha256_SCR(24); my_sha256_SCR(25); my_sha256_SCR(26); my_sha256_SCR(27);
        my_sha256_SCR(28); my_sha256_SCR(29); my_sha256_SCR(30); my_sha256_SCR(31);
        my_sha256_SCR(32); my_sha256_SCR(33); my_sha256_SCR(34); my_sha256_SCR(35);
        my_sha256_SCR(36); my_sha256_SCR(37); my_sha256_SCR(38); my_sha256_SCR(39);
        my_sha256_SCR(40); my_sha256_SCR(41); my_sha256_SCR(42); my_sha256_SCR(43);
        my_sha256_SCR(44); my_sha256_SCR(45); my_sha256_SCR(46); my_sha256_SCR(47);
        my_sha256_SCR(48); my_sha256_SCR(49); my_sha256_SCR(50); my_sha256_SCR(51);
        my_sha256_SCR(52); my_sha256_SCR(53); my_sha256_SCR(54); my_sha256_SCR(55);
        my_sha256_SCR(56); my_sha256_SCR(57); my_sha256_SCR(58); my_sha256_SCR(59);
        my_sha256_SCR(60); my_sha256_SCR(61); my_sha256_SCR(62); my_sha256_SCR(63);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        my_sha256_EXP(0,1,2,3,4,5,6,7, 0); my_sha256_EXP(7,0,1,2,3,4,5,6, 1);
        my_sha256_EXP(6,7,0,1,2,3,4,5, 2); my_sha256_EXP(5,6,7,0,1,2,3,4, 3);
        my_sha256_EXP(4,5,6,7,0,1,2,3, 4); my_sha256_EXP(3,4,5,6,7,0,1,2, 5);
        my_sha256_EXP(2,3,4,5,6,7,0,1, 6); my_sha256_EXP(1,2,3,4,5,6,7,0, 7);
        my_sha256_EXP(0,1,2,3,4,5,6,7, 8); my_sha256_EXP(7,0,1,2,3,4,5,6, 9);
        my_sha256_EXP(6,7,0,1,2,3,4,5,10); my_sha256_EXP(5,6,7,0,1,2,3,4,11);
        my_sha256_EXP(4,5,6,7,0,1,2,3,12); my_sha256_EXP(3,4,5,6,7,0,1,2,13);
        my_sha256_EXP(2,3,4,5,6,7,0,1,14); my_sha256_EXP(1,2,3,4,5,6,7,0,15);
        my_sha256_EXP(0,1,2,3,4,5,6,7,16); my_sha256_EXP(7,0,1,2,3,4,5,6,17);
        my_sha256_EXP(6,7,0,1,2,3,4,5,18); my_sha256_EXP(5,6,7,0,1,2,3,4,19);
        my_sha256_EXP(4,5,6,7,0,1,2,3,20); my_sha256_EXP(3,4,5,6,7,0,1,2,21);
        my_sha256_EXP(2,3,4,5,6,7,0,1,22); my_sha256_EXP(1,2,3,4,5,6,7,0,23);
        my_sha256_EXP(0,1,2,3,4,5,6,7,24); my_sha256_EXP(7,0,1,2,3,4,5,6,25);
        my_sha256_EXP(6,7,0,1,2,3,4,5,26); my_sha256_EXP(5,6,7,0,1,2,3,4,27);
        my_sha256_EXP(4,5,6,7,0,1,2,3,28); my_sha256_EXP(3,4,5,6,7,0,1,2,29);
        my_sha256_EXP(2,3,4,5,6,7,0,1,30); my_sha256_EXP(1,2,3,4,5,6,7,0,31);
        my_sha256_EXP(0,1,2,3,4,5,6,7,32); my_sha256_EXP(7,0,1,2,3,4,5,6,33);
        my_sha256_EXP(6,7,0,1,2,3,4,5,34); my_sha256_EXP(5,6,7,0,1,2,3,4,35);
        my_sha256_EXP(4,5,6,7,0,1,2,3,36); my_sha256_EXP(3,4,5,6,7,0,1,2,37);
        my_sha256_EXP(2,3,4,5,6,7,0,1,38); my_sha256_EXP(1,2,3,4,5,6,7,0,39);
        my_sha256_EXP(0,1,2,3,4,5,6,7,40); my_sha256_EXP(7,0,1,2,3,4,5,6,41);
        my_sha256_EXP(6,7,0,1,2,3,4,5,42); my_sha256_EXP(5,6,7,0,1,2,3,4,43);
        my_sha256_EXP(4,5,6,7,0,1,2,3,44); my_sha256_EXP(3,4,5,6,7,0,1,2,45);
        my_sha256_EXP(2,3,4,5,6,7,0,1,46); my_sha256_EXP(1,2,3,4,5,6,7,0,47);
        my_sha256_EXP(0,1,2,3,4,5,6,7,48); my_sha256_EXP(7,0,1,2,3,4,5,6,49);
        my_sha256_EXP(6,7,0,1,2,3,4,5,50); my_sha256_EXP(5,6,7,0,1,2,3,4,51);
        my_sha256_EXP(4,5,6,7,0,1,2,3,52); my_sha256_EXP(3,4,5,6,7,0,1,2,53);
        my_sha256_EXP(2,3,4,5,6,7,0,1,54); my_sha256_EXP(1,2,3,4,5,6,7,0,55);
        my_sha256_EXP(0,1,2,3,4,5,6,7,56); my_sha256_EXP(7,0,1,2,3,4,5,6,57);
        my_sha256_EXP(6,7,0,1,2,3,4,5,58); my_sha256_EXP(5,6,7,0,1,2,3,4,59);
        my_sha256_EXP(4,5,6,7,0,1,2,3,60); my_sha256_EXP(3,4,5,6,7,0,1,2,61);
        my_sha256_EXP(2,3,4,5,6,7,0,1,62); my_sha256_EXP(1,2,3,4,5,6,7,0,63);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
#endif /* !UNROLL_LOOPS */
    }
}

void my_sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    my_sha256_ctx ctx;

    my_sha256_init(&ctx);
    my_sha256_update(&ctx, message, len);
    my_sha256_final(&ctx, digest);
}

void my_sha256_init(my_sha256_ctx *ctx)
{
#ifndef UNROLL_LOOPS
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = my_sha256_h0[i];
    }
#else
    ctx->h[0] = my_sha256_h0[0]; ctx->h[1] = my_sha256_h0[1];
    ctx->h[2] = my_sha256_h0[2]; ctx->h[3] = my_sha256_h0[3];
    ctx->h[4] = my_sha256_h0[4]; ctx->h[5] = my_sha256_h0[5];
    ctx->h[6] = my_sha256_h0[6]; ctx->h[7] = my_sha256_h0[7];
#endif /* !UNROLL_LOOPS */

    ctx->len = 0;
    ctx->tot_len = 0;
}

void my_sha256_update(my_sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len)
{
	unsigned int partial = ctx->len % MY_SHA256_BLOCK_SIZE;
	int res;

	/* Handle the fast case right here */
	if (partial + len < MY_SHA256_BLOCK_SIZE) {
		ctx->len += len;
		memcpy(ctx->block + partial, message, len);

		return;
	}

//	static int __sha256_ssse3_update(struct shash_desc *desc, const u8 *data,
//				       unsigned int len, unsigned int partial)
	unsigned int done = 0;

	ctx->len += len;

	if (partial) {
		done = MY_SHA256_BLOCK_SIZE - partial;
		memcpy(ctx->block + partial, message, done);
#ifdef USE_ASM
#ifdef AVX
    sha256_avx(ctx->block, ctx->h, 1);
#else
    sha256_sse4(ctx->block, ctx->h, 1);
#endif
#endif
	}

	if (len - done >= MY_SHA256_BLOCK_SIZE) {
			const unsigned int rounds = (len - done) / MY_SHA256_BLOCK_SIZE;

#ifdef USE_ASM
#ifdef AVX
    sha256_avx(message+done, ctx->h, (uint64)rounds);
#else
    printf("before\n");
    sha256_sse4(message+done, ctx->h, (uint64)rounds);
    printf("after\n");
#endif
#endif
		done += rounds * MY_SHA256_BLOCK_SIZE;
	}

	memcpy(ctx->block, message + done, len - done);

}


void my_sha256_final(my_sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

#ifndef UNROLL_LOOPS
    int i;
#endif

    block_nb = (1 + ((MY_SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % MY_SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    my_sha256_transf(ctx, ctx->block, block_nb);

#ifndef UNROLL_LOOPS
    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
#else
   UNPACK32(ctx->h[0], &digest[ 0]);
   UNPACK32(ctx->h[1], &digest[ 4]);
   UNPACK32(ctx->h[2], &digest[ 8]);
   UNPACK32(ctx->h[3], &digest[12]);
   UNPACK32(ctx->h[4], &digest[16]);
   UNPACK32(ctx->h[5], &digest[20]);
   UNPACK32(ctx->h[6], &digest[24]);
   UNPACK32(ctx->h[7], &digest[28]);
#endif /* !UNROLL_LOOPS */
}

///* FIPS 180-2 Validation tests */
//
//#include <stdio.h>
//#include <stdlib.h>
//
//void test(const char *vector, unsigned char *digest,
//          unsigned int digest_size)
//{
//    char output[2 * SHA512_DIGEST_SIZE + 1];
//    int i;
//
//    output[2 * digest_size] = '\0';
//
//    for (i = 0; i < (int) digest_size ; i++) {
//       sprintf(output + 2 * i, "%02x", digest[i]);
//    }
//
//    printf("H: %s\n", output);
//    if (strcmp(vector, output)) {
//        fprintf(stderr, "Test failed.\n");
//        exit(EXIT_FAILURE);
//    }
//}
//
//int main(void)
//{
//    static const char *vectors[4][3] =
//    {   /* SHA-224 */
//        {
//        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
//        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
//        "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
//        },
//        /* SHA-256 */
//        {
//        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
//        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
//        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
//        },
//        /* SHA-384 */
//        {
//        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
//        "8086072ba1e7cc2358baeca134c825a7",
//        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
//        "fcc7c71a557e2db966c3e9fa91746039",
//        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
//        "07b8b3dc38ecc4ebae97ddd87f3d8985",
//        },
//        /* SHA-512 */
//        {
//        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
//        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
//        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
//        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
//        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
//        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
//        }
//    };
//
//    static const char message1[] = "abc";
//    static const char message2a[] = "abcdbcdecdefdefgefghfghighijhi"
//                                    "jkijkljklmklmnlmnomnopnopq";
//    static const char message2b[] = "abcdefghbcdefghicdefghijdefghijkefghij"
//                                    "klfghijklmghijklmnhijklmnoijklmnopjklm"
//                                    "nopqklmnopqrlmnopqrsmnopqrstnopqrstu";
//    unsigned char *message3;
//    unsigned int message3_len = 1000000;
//    unsigned char digest[SHA512_DIGEST_SIZE];
//
//    message3 = (unsigned char*)malloc(message3_len);
//    if (message3 == NULL) {
//        fprintf(stderr, "Can't allocate memory\n");
//        return -1;
//    }
//    memset(message3, 'a', message3_len);
//
//    printf("SHA-2 FIPS 180-2 Validation tests\n\n");
//    printf("SHA-224 Test vectors\n");
//
//    sha224((const unsigned char *) message1, strlen(message1), digest);
//    test(vectors[0][0], digest, SHA224_DIGEST_SIZE);
//    sha224((const unsigned char *) message2a, strlen(message2a), digest);
//    test(vectors[0][1], digest, SHA224_DIGEST_SIZE);
//    sha224(message3, message3_len, digest);
//    test(vectors[0][2], digest, SHA224_DIGEST_SIZE);
//    printf("\n");
//
//    printf("SHA-256 Test vectors\n");
//
//    my_sha256((const unsigned char *) message1, strlen(message1), digest);
//    test(vectors[1][0], digest, my_sha256_DIGEST_SIZE);
//    my_sha256((const unsigned char *) message2a, strlen(message2a), digest);
//    test(vectors[1][1], digest, my_sha256_DIGEST_SIZE);
//    my_sha256(message3, message3_len, digest);
//    test(vectors[1][2], digest, my_sha256_DIGEST_SIZE);
//    printf("\n");
//
//    printf("SHA-512 Test vectors\n");
//
//    sha512((const unsigned char *) message1, strlen(message1), digest);
//    test(vectors[3][0], digest, SHA512_DIGEST_SIZE);
//    sha512((const unsigned char *) message2b, strlen(message2b), digest);
//    test(vectors[3][1], digest, SHA512_DIGEST_SIZE);
//    sha512(message3, message3_len, digest);
//    test(vectors[3][2], digest, SHA512_DIGEST_SIZE);
//    printf("\n");
//
//    printf("All tests passed.\n");
//
//    return 0;
//}
//
