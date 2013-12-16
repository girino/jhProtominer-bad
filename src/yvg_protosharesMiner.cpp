#include"global.h"

#define OLDVERSION 1

#define MAX_MOMENTUM_NONCE		67108864
#define SEARCH_SPACE_BITS		50
#define BIRTHDAYS_PER_HASH		8

__declspec(thread) uint32* __collisionMap = NULL;

volatile uint32 totalCollisionCount = 0;
volatile uint32 totalShareCount = 0;
volatile uint32 valid_shares = 0;
volatile uint32 invalid_shares = 0;
volatile uint32 false_positives = 0;
volatile uint32 numSha256Runs = 0;
volatile uint32 numSha512Runs = 0;

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
	sha512_ctx c512;
	sha512_init(&c512);
	sha512_update(&c512, tempHash, 32+4);
	sha512_final(&c512, (unsigned char*)resultHash);
	uint64 birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	// get birthday B
	*(uint32*)tempHash = indexB&~7;
	sha512_init(&c512);
	sha512_update(&c512, tempHash, 32+4);
	sha512_final(&c512, (unsigned char*)resultHash);
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
	bool hashMeetsTarget = true;
	uint32* generatedHash32 = (uint32*)proofOfWorkHash;
	uint32* targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget = false;
			break;
		}
	}
	if( hashMeetsTarget )
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
	hashMeetsTarget = true;
	generatedHash32 = (uint32*)proofOfWorkHash;
	targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget = false;
			break;
		}
	}
	if( hashMeetsTarget )
	{
		totalShareCount++;
		jhProtominer_submitShare(block);
	}
	return true;
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define COLLISION_TABLE_BITS	(27)
#define COLLISION_TABLE_SIZE	134217728 // (1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		5
#define COLLISION_KEY_MASK		0xF8000000 //(0xFFFFFFFF<<(COLLISION_TABLE_BITS))

void protoshares_process_512(minerProtosharesBlock_t* block) {

	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	// init collision map
	if( __collisionMap == NULL ) {
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	}
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);

	uint8 inHash[32+4];
	uint64 outHash[BIRTHDAYS_PER_HASH];
	sha512_ctx c512;
	memcpy(inHash+4, midHash, 32);

	for (uint32 n = 0; n < MAX_MOMENTUM_NONCE; n+= BIRTHDAYS_PER_HASH) {
		sha512_init(&c512);
		*(uint32*)inHash = n;
		sha512_update_final(&c512, inHash, 36, (unsigned char*)(outHash));

		for(uint32 f=0; f<8; f++)
		{
			uint64 birthdayB = outHash[f] >> (64ULL-SEARCH_SPACE_BITS);
			uint32 collisionKey = (uint32)((birthdayB>>18) & COLLISION_KEY_MASK);
			uint64 birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
			if( collisionIndices[birthday] && ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey))
			{
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, n+f);
			} else {
				collisionIndices[birthday] = n+f | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}
