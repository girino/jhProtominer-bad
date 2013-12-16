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

bool protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB, uint64 birthdayB)
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
	numSha512Runs++;
	uint64 birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	// get birthday B
//	*(uint32*)tempHash = indexB&~7;
//	sha512_init(&c512);
//	sha512_update(&c512, tempHash, 32+4);
//	sha512_final(&c512, (unsigned char*)resultHash);
//	uint64 birthdayB = resultHash[indexB&7] >> (64ULL-SEARCH_SPACE_BITS);
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
	numSha256Runs+=4;
	return true;
}

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(27)
#define COLLISION_TABLE_SIZE	134217728 // (1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		5
#define COLLISION_KEY_MASK		0xF8000000 //(0xFFFFFFFF<<(COLLISION_TABLE_BITS))

void protoshares_process_512(minerProtosharesBlock_t* block)
{
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)block, 80);
	sha256_final(&c256, midHash);
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)midHash, 32);
	sha256_final(&c256, midHash);
	numSha256Runs+=2;
	// init collision map
	if( __collisionMap == NULL ) {
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	}
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	uint8 tempHash[32+4];
	sha512_ctx c512;
	uint32 step = BIRTHDAYS_PER_HASH * CACHED_HASHES;
	uint64 resultHashStorage[step];
	memcpy(tempHash+4, midHash, 32);
	for(uint32 n=0; n<(MAX_MOMENTUM_NONCE); n += step)
	{
		if( block->height != monitorCurrentBlockHeight )
			break;
		for(uint32 m8=0; m8<step; m8+=BIRTHDAYS_PER_HASH)
		{
			sha512_init(&c512);
			*(uint32*)tempHash = n+m8;
			sha512_update_final(&c512, tempHash, 36, (unsigned char*)(resultHashStorage+m8));
			numSha512Runs++;
		}
		for(uint32 m8=0; m8<step; m8+=BIRTHDAYS_PER_HASH)
		{
			uint64* resultHash = resultHashStorage + m8;
			uint32 i = n + m8;
#ifndef UNROLL_LOOP
			for(uint32 f=0; f<8; f++)
			{
				uint64 birthdayB = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthdayB>>18) & COLLISION_KEY_MASK);
				//uint64 birthday = birthdayB % COLLISION_TABLE_SIZE;
				uint64 birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
				if( collisionIndices[birthday] && ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey))
				{
					protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f, birthdayB);
				} else {
					collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
				}
			}
#else
			uint64 birthdayB0 = resultHash[0] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB1 = resultHash[1] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB2 = resultHash[2] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB3 = resultHash[3] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB4 = resultHash[4] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB5 = resultHash[5] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB6 = resultHash[6] >> (64ULL-SEARCH_SPACE_BITS);
			uint64 birthdayB7 = resultHash[7] >> (64ULL-SEARCH_SPACE_BITS);
			uint32 collisionKey0 = (uint32)((birthdayB0>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey1 = (uint32)((birthdayB1>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey2 = (uint32)((birthdayB2>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey3 = (uint32)((birthdayB3>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey4 = (uint32)((birthdayB4>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey5 = (uint32)((birthdayB5>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey6 = (uint32)((birthdayB6>>18) & COLLISION_KEY_MASK);
			uint32 collisionKey7 = (uint32)((birthdayB7>>18) & COLLISION_KEY_MASK);
			uint64 birthday0 = birthdayB0 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday1 = birthdayB1 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday2 = birthdayB2 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday3 = birthdayB3 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday4 = birthdayB4 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday5 = birthdayB5 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday6 = birthdayB6 & (COLLISION_TABLE_SIZE-1);
			uint64 birthday7 = birthdayB7 & (COLLISION_TABLE_SIZE-1);
			if( collisionIndices[birthday0] && ((collisionIndices[birthday0]&COLLISION_KEY_MASK) == collisionKey0))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday0]&~COLLISION_KEY_MASK, i, birthdayB0);
			if( collisionIndices[birthday1] && ((collisionIndices[birthday1]&COLLISION_KEY_MASK) == collisionKey1))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday1]&~COLLISION_KEY_MASK, i+1, birthdayB1);
			if( collisionIndices[birthday2] && ((collisionIndices[birthday2]&COLLISION_KEY_MASK) == collisionKey2))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday2]&~COLLISION_KEY_MASK, i+2, birthdayB2);
			if( collisionIndices[birthday3] && ((collisionIndices[birthday3]&COLLISION_KEY_MASK) == collisionKey3))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday3]&~COLLISION_KEY_MASK, i+3, birthdayB3);
			if( collisionIndices[birthday4] && ((collisionIndices[birthday4]&COLLISION_KEY_MASK) == collisionKey4))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday4]&~COLLISION_KEY_MASK, i+4, birthdayB4);
			if( collisionIndices[birthday5] && ((collisionIndices[birthday5]&COLLISION_KEY_MASK) == collisionKey5))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday5]&~COLLISION_KEY_MASK, i+5, birthdayB5);
			if( collisionIndices[birthday6] && ((collisionIndices[birthday6]&COLLISION_KEY_MASK) == collisionKey6))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday6]&~COLLISION_KEY_MASK, i+6, birthdayB6);
			if( collisionIndices[birthday7] && ((collisionIndices[birthday7]&COLLISION_KEY_MASK) == collisionKey7))
				protoshares_revalidateCollision(block, midHash, collisionIndices[birthday7]&~COLLISION_KEY_MASK, i+7, birthdayB7);

			collisionIndices[birthday0] = i | collisionKey0; // we have 6 bits available for validation
			collisionIndices[birthday1] = i+1 | collisionKey1; // we have 6 bits available for validation
			collisionIndices[birthday2] = i+2 | collisionKey2; // we have 6 bits available for validation
			collisionIndices[birthday3] = i+3 | collisionKey3; // we have 6 bits available for validation
			collisionIndices[birthday4] = i+4 | collisionKey4; // we have 6 bits available for validation
			collisionIndices[birthday5] = i+5 | collisionKey5; // we have 6 bits available for validation
			collisionIndices[birthday6] = i+6 | collisionKey6; // we have 6 bits available for validation
			collisionIndices[birthday7] = i+7 | collisionKey7; // we have 6 bits available for validation

			#endif
		}
	}
}

