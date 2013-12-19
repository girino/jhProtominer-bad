#include"global.h"
#include "sph_sha2.h"
#include "sph_types.h"
#include <openssl/sha.h>
#include "sha512.h"
#include "sha2.h"
#include "sph_sha2.h"
#include "protoshares_validator.h"

void _sha512(_sha512_context* ctx, const unsigned char* data, size_t len, const unsigned char* result) {

#ifdef PROFILE_SHA
		uint32 firsTicksha = GetTickCount();
#endif

#ifdef USE_SPH
	sph_sha512_init(ctx);
	sph_sha512_update_final(ctx, data, len, (unsigned char*)(result));
#elif USE_OPENSSL
	SHA512_Init(ctx);
	SHA512_Update(ctx, data, len);
	SHA512_Final((unsigned char*)(result), ctx);
#elif USE_ASM
	SHA512_InitASM(ctx);
	SHA512_UpdateASM(ctx, data, len);
	SHA512_FinalASM(ctx, (unsigned char*)(result));
#else
	sha512_init(ctx);
	sha512_update_final(ctx, data, len, (unsigned char*)(result));
#endif

#ifdef PROFILE_SHA
		uint32 lastTicksha = GetTickCount();
		shatime += (lastTicksha - firsTicksha);
		numSha512Runs++;
#endif

}


volatile uint32 totalCollisionCount = 0;
volatile uint32 totalShareCount = 0;
volatile uint32 valid_shares = 0;
volatile uint32 invalid_shares = 0;
volatile uint32 false_positives = 0;
volatile uint32 numSha256Runs = 0;
volatile uint32 numSha512Runs = 0;
volatile uint32 looptime = 0;
volatile uint32 shatime = 0;
volatile uint32 numloops = 0;

int protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB)
{
	//if( indexA > MAX_MOMENTUM_NONCE )
	//	printf("indexA out of range\n");
	//if( indexB > MAX_MOMENTUM_NONCE )
	//	printf("indexB out of range\n");
	//if( indexA == indexB )
	//	printf("indexA == indexB");
	uint8 tempHash[32+4];
	uint64 resultHash[8];
	memcpy(tempHash+4, midHash, 32);
	_sha512_context c512;
	// get birthday B
	*(uint32*)tempHash = indexB&~7;
	_sha512(&c512, tempHash, 32+4, (unsigned char*)resultHash);
	uint64 birthdayB = resultHash[indexB&7] >> (64ULL-SEARCH_SPACE_BITS);
	// get birthday A
	*(uint32*)tempHash = indexA&~7;
	_sha512(&c512, tempHash, 32+4, (unsigned char*)resultHash);
	int matches = 0;
	int i = 0;
	for (; i<8; i++) {
		uint64 birthdayA = resultHash[i] >> (64ULL-SEARCH_SPACE_BITS);
		if( birthdayA == birthdayB )
		{
			matches = 1;
			break;
		}
	}
	if (!matches) {
		false_positives++;
		return -1;
	}
	// birthday collision found
	totalCollisionCount += 2; // we can use every collision twice -> A B and B A
	//printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
	// get full block hash (for A B)
	block->birthdayA = indexA+i;
	block->birthdayB = indexB;
	uint8 proofOfWorkHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80+8);
	sha256_final(&c256, proofOfWorkHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
	sha256_final(&c256, proofOfWorkHash);
	int hashMeetsTarget1 = 1;
	uint32* generatedHash32 = (uint32*)proofOfWorkHash;
	uint32* targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget1 = 1;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget1 = 0;
			break;
		}
	}
	if( hashMeetsTarget1 )
	{
		totalShareCount++;
		jhProtominer_submitShare(block);
	}
	// get full block hash (for B A)
	block->birthdayA = indexB;
	block->birthdayB = indexA+1;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80+8);
	sha256_final(&c256, proofOfWorkHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
	sha256_final(&c256, proofOfWorkHash);
	int hashMeetsTarget2 = 1;
	generatedHash32 = (uint32*)proofOfWorkHash;
	targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget2 = 1;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget2 = 0;
			break;
		}
	}
	if( hashMeetsTarget2 )
	{
		totalShareCount++;
		jhProtominer_submitShare(block);
	}
	return hashMeetsTarget1 || hashMeetsTarget2; // only return true on submit
}
