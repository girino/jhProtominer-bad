/*
 * Cryptographic API.
 *
 * Glue code for the SHA256 Secure Hash Algorithm assembler
 * implementation using supplemental SSE3 / AVX / AVX2 instructions.
 *
 * This file is based on sha256_generic.c
 *
 * Copyright (C) 2013 Intel Corporation.
 *
 * Author:
 *     Tim Chen <tim.c.chen@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#define CONFIG_AS_AVX 1
#define CONFIG_AS_AVX2 1

/*#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/cryptohash.h>
#include <types.h>
#include <crypto/sha.h>
#include <asm/byteorder.h>
#include <asm/i387.h>
#include <asm/xcr.h>
#include <asm/xsave.h>*/
#include <string.h>
#include "sha.h"

//LITTLE ENDIAN ONLY

#if defined(__MINGW32__) || defined(__MINGW64__)

static __inline unsigned short
bswap_16 (unsigned short __x)
{
  return (__x >> 8) | (__x << 8);
}

static __inline unsigned int
bswap_32 (unsigned int __x)
{
  return (bswap_16 (__x & 0xffff) << 16) | (bswap_16 (__x >> 16));
}

static __inline unsigned long long
bswap_64 (unsigned long long __x)
{
  return (((unsigned long long) bswap_32 (__x & 0xffffffffull)) << 32) | (bswap_32 (__x >> 32));
}

#define BYTESWAP(x) bswap_32(x)
#define BYTESWAP64(x) bswap_64(x)

#elif defined(__APPLE__)

#include <libkern/OSByteOrder.h>

#define BYTESWAP(x) OSSwapBigToHostInt32(x)
#define BYTESWAP64(x) OSSwapBigToHostInt64(x)

#else

#include <endian.h> //glibc

#define BYTESWAP(x) be32toh(x)
#define BYTESWAP64(x) be64toh(x)

#endif /* defined(__MINGW32__) || defined(__MINGW64__) */

extern "C" void sha256_sse4(const char *data, u32 *digest,
				     u64 rounds);
#ifdef CONFIG_AS_AVX
extern "C" void sha256_avx(const char *data, u32 *digest,
				     u64 rounds);
#endif
#ifdef CONFIG_AS_AVX2
extern "C" void sha256_rorx_x8ms(const char *data, u32 *digest,
				     u64 rounds);
#endif

//extern void (*sha256_transform_asm)(const char *, u32 *, u64);

#ifdef SSE4
#define sha256_transform_asm sha256_sse4
#elif AVX
#define sha256_transform_asm sha256_avx
#else
#define sha256_transform_asm sha256_rorx_x8ms
#endif

int sha256_ssse3_init(struct sha256_state *sctx)
{

	sctx->state[0] = SHA256_H0;
	sctx->state[1] = SHA256_H1;
	sctx->state[2] = SHA256_H2;
	sctx->state[3] = SHA256_H3;
	sctx->state[4] = SHA256_H4;
	sctx->state[5] = SHA256_H5;
	sctx->state[6] = SHA256_H6;
	sctx->state[7] = SHA256_H7;
	sctx->count = 0;

	return 0;
}

static int __sha256_ssse3_update(struct sha256_state *sctx, const u8 *data,
			       unsigned int len, unsigned int partial)
{
	unsigned int done = 0;

	sctx->count += len;

	if (partial) {
		done = SHA256_BLOCK_SIZE - partial;
		memcpy(sctx->buf + partial, data, done);
		sha256_transform_asm((char*)(sctx->buf), sctx->state, 1);
	}

	if (len - done >= SHA256_BLOCK_SIZE) {
		const unsigned int rounds = (len - done) / SHA256_BLOCK_SIZE;

		sha256_transform_asm((char*)(data + done), sctx->state, (u64) rounds);

		done += rounds * SHA256_BLOCK_SIZE;
	}

	memcpy(sctx->buf, data + done, len - done);

	return 0;
}

int sha256_ssse3_update(struct sha256_state *sctx, const u8 *data,
			     unsigned int len)
{
	unsigned int partial = sctx->count % SHA256_BLOCK_SIZE;
	int res;

	/* Handle the fast case right here */
	if (partial + len < SHA256_BLOCK_SIZE) {
		sctx->count += len;
		memcpy(sctx->buf + partial, data, len);

		return 0;
	}

//	if (!irq_fpu_usable()) {
//		res = crypto_sha256_update(sctx, data, len);
//	} else {
//		kernel_fpu_begin();
		res = __sha256_ssse3_update(sctx, data, len, partial);
//		kernel_fpu_end();
//	}

	return res;
}


/* Add padding and return the message digest. */
int sha256_ssse3_final(struct sha256_state *sctx, u8 *out)
{
	unsigned int i, index, padlen;
	__be32 *dst = (__be32 *)out;
	__be64 bits;
	static const u8 padding[SHA256_BLOCK_SIZE] = { 0x80, };

	bits = BYTESWAP64(sctx->count << 3);

	/* Pad out to 56 mod 64 and append length */
	index = sctx->count % SHA256_BLOCK_SIZE;
	padlen = (index < 56) ? (56 - index) : ((SHA256_BLOCK_SIZE+56)-index);

//	if (!irq_fpu_usable()) {
//		crypto_sha256_update(sctx, padding, padlen);
//		crypto_sha256_update(sctx, (const u8 *)&bits, sizeof(bits));
//	} else {
//		kernel_fpu_begin();
		/* We need to fill a whole block for __sha256_ssse3_update() */
		if (padlen <= 56) {
			sctx->count += padlen;
			memcpy(sctx->buf + index, padding, padlen);
		} else {
			__sha256_ssse3_update(sctx, padding, padlen, index);
		}
		__sha256_ssse3_update(sctx, (const u8 *)&bits,
					sizeof(bits), 56);
//		kernel_fpu_end();
//	}

	/* Store state in digest */
	for (i = 0; i < 8; i++)
		dst[i] = BYTESWAP(sctx->state[i]);

	/* Wipe context */
	memset(sctx, 0, sizeof(*sctx));

	return 0;
}

static int sha256_ssse3_export(struct sha256_state *sctx, void *out)
{
	memcpy(out, sctx, sizeof(*sctx));

	return 0;
}

static int sha256_ssse3_import(struct sha256_state *sctx, const void *in)
{
	memcpy(sctx, in, sizeof(*sctx));

	return 0;
}

static int sha224_ssse3_init(struct sha256_state *sctx)
{

	sctx->state[0] = SHA224_H0;
	sctx->state[1] = SHA224_H1;
	sctx->state[2] = SHA224_H2;
	sctx->state[3] = SHA224_H3;
	sctx->state[4] = SHA224_H4;
	sctx->state[5] = SHA224_H5;
	sctx->state[6] = SHA224_H6;
	sctx->state[7] = SHA224_H7;
	sctx->count = 0;

	return 0;
}

static int sha224_ssse3_final(struct sha256_state *sctx, u8 *hash)
{
	u8 D[SHA256_DIGEST_SIZE];

	sha256_ssse3_final(sctx, D);

	memcpy(hash, D, SHA224_DIGEST_SIZE);
	memset(D, 0, SHA256_DIGEST_SIZE);

	return 0;
}

