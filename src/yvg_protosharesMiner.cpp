#include"global.h"
#include "sph_sha2.h"
#include "sph_types.h"
#include <openssl/sha.h>
#include "sha512.h"
#include "sha2.h"
#include "sph_sha2.h"
#include "protoshares_validator.h"
#include "protosharesMiner.h"

void protoshares_process(minerProtosharesBlock_t* block, uint32** __collisionMap) {

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

	for (uint32 n = 0; n < MAX_MOMENTUM_NONCE; n+= BIRTHDAYS_PER_HASH) {
//	uint32 n = 0;
//	while (1) {
//		if( n >= MAX_MOMENTUM_NONCE ) {
//			//only normal exits count
//			break;
//		}
		if( block->height != monitorCurrentBlockHeight )
			break;

		*(uint32*)inHash = n;
		_sha512(&c512, inHash, 36, (unsigned char*)(outHash));

		// unroll the loop
#ifndef UNROLL_LOOPS
		for(register uint32 f=0; f<BIRTHDAYS_PER_HASH; f++)
		{
			uint64 birthdayB = outHash[f]>> (64-SEARCH_SPACE_BITS);
			uint32 collisionKey = (uint32)((birthdayB>>18) & 0xff800000);
			uint64 birthday = birthdayB & 0x7ffffff;
			if(((collisionIndices[birthday]&0xff800000) == collisionKey))
			{
				protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday] & 0x7fffff) << 0x3, n+f);
			} else {
				collisionIndices[birthday] = collisionKey | (n/8); // we have 6 bits available for validation
			}
		}
#else
		int i = 0;
repeat8(
		uint64 birthdayB = outHash[i]>> (64-SEARCH_SPACE_BITS);
		uint32 collisionKey = (uint32)((birthdayB>>18) & 0xff800000);
		uint64 birthday = birthdayB & 0x7ffffff;
		if(((collisionIndices[birthday]&0xff800000) == collisionKey))
		{
			protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday] & 0x7fffff) << 0x3, n+i);
		} else {
			collisionIndices[birthday] = collisionKey | (n/8); // we have 6 bits available for validation
		}
		i++;
)

#endif
//		n+=BIRTHDAYS_PER_HASH;
	}
#ifdef PROFILE
	uint32 lastTick = GetTickCount();
	looptime += (lastTick - firstTick);
	numloops++;
#endif

}
