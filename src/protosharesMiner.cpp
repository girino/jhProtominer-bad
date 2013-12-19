#include"global.h"
#include "sph_sha2.h"
#include "sph_types.h"
#include <openssl/sha.h>
#include "sha512.h"
#include "sha2.h"
#include "sph_sha2.h"
#include "protoshares_validator.h"
#include "protosharesMiner.h"

#define CACHED_HASHES 512

void protoshares_process(minerProtosharesBlock_t* block, uint32** __collisionMap) {

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
	if( *__collisionMap == NULL ) {
		*__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	}
	uint32* collisionIndices = *__collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	uint8 tempHash[32+4];
	_sha512_context c512;
	uint32 step = BIRTHDAYS_PER_HASH * CACHED_HASHES;
	uint64 resultHashStorage[step];
	memcpy(tempHash+4, midHash, 32);

	// count full loop time
	uint32 firstTick = GetTickCount();

	for(uint32 n=0; n<(MAX_MOMENTUM_NONCE); n += step)
	{
		if( block->height != monitorCurrentBlockHeight )
			break;
		for(uint32 m8=0; m8<step; m8+=BIRTHDAYS_PER_HASH)
		{
			*(uint32*)tempHash = n+m8;
			_sha512(&c512, tempHash, 36, (unsigned char*)(resultHashStorage+m8));
			numSha512Runs++;
		}
		for(uint32 m8=0; m8<step; m8+=BIRTHDAYS_PER_HASH)
		{
			uint64* resultHash = resultHashStorage + m8;
			uint32 i = n + m8;
#ifndef UNROLL_LOOPS
			for(register uint32 f=0; f<BIRTHDAYS_PER_HASH; f++)
			{
				uint64 birthdayB = resultHash[f]>> (64-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthdayB>>18) & 0xff800000);
				uint64 birthday = birthdayB & 0x7ffffff;
				if(((collisionIndices[birthday]&0xff800000) == collisionKey))
				{
					protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday] & 0x7fffff) << 0x3, i+f);
				} else {
					collisionIndices[birthday] = collisionKey | (i/8); // we have 6 bits available for validation
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
			uint32 collisionKey0 = (uint32)((birthdayB0>>18) & 0xff800000);
			uint32 collisionKey1 = (uint32)((birthdayB1>>18) & 0xff800000);
			uint32 collisionKey2 = (uint32)((birthdayB2>>18) & 0xff800000);
			uint32 collisionKey3 = (uint32)((birthdayB3>>18) & 0xff800000);
			uint32 collisionKey4 = (uint32)((birthdayB4>>18) & 0xff800000);
			uint32 collisionKey5 = (uint32)((birthdayB5>>18) & 0xff800000);
			uint32 collisionKey6 = (uint32)((birthdayB6>>18) & 0xff800000);
			uint32 collisionKey7 = (uint32)((birthdayB7>>18) & 0xff800000);
			uint64 birthday0 = birthdayB0 & 0x7ffffff;
			uint64 birthday1 = birthdayB1 & 0x7ffffff;
			uint64 birthday2 = birthdayB2 & 0x7ffffff;
			uint64 birthday3 = birthdayB3 & 0x7ffffff;
			uint64 birthday4 = birthdayB4 & 0x7ffffff;
			uint64 birthday5 = birthdayB5 & 0x7ffffff;
			uint64 birthday6 = birthdayB6 & 0x7ffffff;
			uint64 birthday7 = birthdayB7 & 0x7ffffff;
			if( ((collisionIndices[birthday0]&0xff800000) == collisionKey0))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday0] & 0x7fffff) << 0x3, i);
			if( ((collisionIndices[birthday1]&0xff800000) == collisionKey1))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday1] & 0x7fffff) << 0x3, i+1);
			if( ((collisionIndices[birthday2]&0xff800000) == collisionKey2))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday2] & 0x7fffff) << 0x3, i+2);
			if( ((collisionIndices[birthday3]&0xff800000) == collisionKey3))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday3] & 0x7fffff) << 0x3, i+3);
			if( ((collisionIndices[birthday4]&0xff800000) == collisionKey4))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday4] & 0x7fffff) << 0x3, i+4);
			if( ((collisionIndices[birthday5]&0xff800000) == collisionKey5))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday5] & 0x7fffff) << 0x3, i+5);
			if( ((collisionIndices[birthday6]&0xff800000) == collisionKey6))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday6] & 0x7fffff) << 0x3, i+6);
			if( ((collisionIndices[birthday7]&0xff800000) == collisionKey7))
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday7] & 0x7fffff) << 0x3, i+7);

			collisionIndices[birthday0] = i/8 | collisionKey0; // we have 6 bits available for validation
			collisionIndices[birthday1] = i/8 | collisionKey1; // we have 6 bits available for validation
			collisionIndices[birthday2] = i/8 | collisionKey2; // we have 6 bits available for validation
			collisionIndices[birthday3] = i/8 | collisionKey3; // we have 6 bits available for validation
			collisionIndices[birthday4] = i/8 | collisionKey4; // we have 6 bits available for validation
			collisionIndices[birthday5] = i/8 | collisionKey5; // we have 6 bits available for validation
			collisionIndices[birthday6] = i/8 | collisionKey6; // we have 6 bits available for validation
			collisionIndices[birthday7] = i/8 | collisionKey7; // we have 6 bits available for validation

			#endif
		}
	}
	if( block->height == monitorCurrentBlockHeight ) {
		//only normal exits count
		uint32 lastTick = GetTickCount();
		looptime += (lastTick - firstTick);
		numloops++;
	}
}
