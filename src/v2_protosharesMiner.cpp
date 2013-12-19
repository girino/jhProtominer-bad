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

		birthdayB = outHash[n&7]>> (64-SEARCH_SPACE_BITS);
		collisionKey = (uint32)((birthdayB>>18) & 0xff800000);
		birthday = birthdayB & 0x7ffffff;
        if ((collisionIndices[birthday] & 0xff800000) != collisionKey) {
        	collisionIndices[birthday] = collisionKey | (n/8);
        } else {
        	protoshares_revalidateCollision(block, midHash, (collisionIndices[birthday] & 0x7fffff) << 0x3, n);
        	//printf("%X %X\n", ((collisionKey | (n/8)) & 0x7fffff) << 0x3, n);
        }

//			birthdayB = outHash[n&7]>> (64-SEARCH_SPACE_BITS);
//			collisionKey = (uint32)((birthdayB>>18) & COLLISION_KEY_MASK);
//			//birthday = birthdayB & (COLLISION_TABLE_SIZE-1);
//			birthday = birthdayB % (COLLISION_TABLE_SIZE-1); // good chances of being prime, less collisions i hooe
//			if( collisionIndices[birthday] && ((collisionIndices[birthday]&COLLISION_KEY_MASK) == collisionKey))
//			{
//				// not checking all the time
//				if( block->height != monitorCurrentBlockHeight )
//					return;
//				if (protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, n)) {
//					return; // if found a share, go home. no 2 shares on the same search space...
//				}
//			} else {
//				collisionIndices[birthday] = n | collisionKey; // we have 6 bits available for validation
//			}
//		}
		n++;

	}
#ifdef PROFILE
	uint32 lastTick = GetTickCount();
	looptime += (lastTick - firstTick);
	numloops++;
#endif

}
