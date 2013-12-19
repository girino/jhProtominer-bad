#ifndef PROTOSHARES_VALIDATOR_H
#define PROTOSHARES_VALIDATOR_H

// tentando uma macro
#define repeat2(x) {x} {x}
#define repeat4(x) repeat2(x) repeat2(x)
#define repeat8(x) repeat4(x) repeat4(x)
#define repeat16(x) repeat8(x) repeat8(x)
#define repeat32(x) repeat16(x) repeat16(x)
#define repeat64(x) repeat32(x) repeat32(x)

#define SEARCH_SPACE_BITS		50

// macros
#ifdef USE_SPH
#define _sha512_context sph_sha512_context
#elif USE_ASM
#define _sha512_context SHA512_ContextASM
#elif USE_OPENSSL
#define _sha512_context SHA512_CTX
#else
#define _sha512_context sha512_ctx
#endif

void _sha512(_sha512_context* ctx, const unsigned char* data, size_t len, const unsigned char* result);
int protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB);


#endif
