#include"global.h"
#include "sph_sha2.h"
#include "sph_types.h"
#include <openssl/sha.h>
#include "sha512.h"
#include "sha2.h"
#include "sph_sha2.h"

// tentando uma macro
#define repeat2(x) {x} {x}
#define repeat4(x) repeat2(x) repeat2(x)
#define repeat8(x) repeat4(x) repeat4(x)
#define repeat16(x) repeat8(x) repeat8(x)
#define repeat32(x) repeat16(x) repeat16(x)
#define repeat64(x) repeat32(x) repeat32(x)

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

__inline void _sha512(_sha512_context* ctx, const unsigned char* data, size_t len, const unsigned char* result) {

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

#define OLDVERSION 1

#define MAX_MOMENTUM_NONCE		0x4000000
#define SEARCH_SPACE_BITS		50
#define BIRTHDAYS_PER_HASH		8

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

bool protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB)
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
	// get birthday A
	*(uint32*)tempHash = indexA&~7;
	_sha512_context c512;
	_sha512(&c512, tempHash, 32+4, (unsigned char*)resultHash);
	uint64 birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	// get birthday B
	*(uint32*)tempHash = indexB&~7;
	_sha512(&c512, tempHash, 32+4, (unsigned char*)resultHash);
	uint64 birthdayB = resultHash[indexB&7] >> (64ULL-SEARCH_SPACE_BITS);
	if( birthdayA != birthdayB )
	{
		false_positives++;
		return false; // invalid collision
	}
	// birthday collision found
	totalCollisionCount += 2; // we can use every collision twice -> A B and B A
	//printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
	// get full block hash (for A B)
	block->birthdayA = indexA;
	block->birthdayB = indexB;
	uint8 proofOfWorkHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80+8);
	sha256_final(&c256, proofOfWorkHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
	sha256_final(&c256, proofOfWorkHash);
	bool hashMeetsTarget1 = true;
	uint32* generatedHash32 = (uint32*)proofOfWorkHash;
	uint32* targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget1 = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget1 = false;
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
	block->birthdayB = indexA;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80+8);
	sha256_final(&c256, proofOfWorkHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)proofOfWorkHash, 32);
	sha256_final(&c256, proofOfWorkHash);
	bool hashMeetsTarget2 = true;
	generatedHash32 = (uint32*)proofOfWorkHash;
	targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget2 = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget2 = false;
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

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define COLLISION_TABLE_BITS	(27)
#define COLLISION_TABLE_SIZE	0x8000000 // (1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		5
#define COLLISION_KEY_MASK		0xF8000000 //(0xFFFFFFFF<<(COLLISION_TABLE_BITS))

void protoshares_process_512(minerProtosharesBlock_t* block, uint32** __collisionMap) {

	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	// init collision map
	if( *__collisionMap == NULL ) {
		*__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	}
	uint32* collisionIndices = *__collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);

	uint8 inHash[32+4];
	uint64 outHash[BIRTHDAYS_PER_HASH];

	_sha512_context c512;
	memcpy(inHash+4, midHash, 32);

#ifdef PROFILE
	uint32 firstTick = GetTickCount();
#endif


	uint32 n = 0;
	uint64 birthdayB;
	uint32 collisionKey;
	uint64 birthday;
	while (n < MAX_MOMENTUM_NONCE) {

		if (0 == (n&7)) { // every 8 steps I calculate sha512
			*(uint32*)inHash = n;
			_sha512(&c512, inHash, 36, (unsigned char*)(outHash));

		}

//		for (uint32 i=n+8;n<i;n++) {
			birthdayB = outHash[n&7] >> (64-SEARCH_SPACE_BITS);
			collisionKey = (uint32)((birthdayB>>18) & COLLISION_KEY_MASK);
			//birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
			birthday = birthdayB % (COLLISION_TABLE_SIZE-1); // good chances of being prime, less collisions i hooe
			if( collisionIndices[birthday] && ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey))
			{
				// not checking all the time
				if( block->height != monitorCurrentBlockHeight )
					return;
				if (protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, n)) {
					return; // if found a share, go home. no 2 shares on the same search space...
				}
			} else {
				collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
			}
//		}
		n++;

	}
#ifdef PROFILE
	uint32 lastTick = GetTickCount();
	looptime += (lastTick - firstTick);
	numloops++;
#endif

}
