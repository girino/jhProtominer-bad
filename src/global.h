
#ifdef __WIN32__
#pragma comment(lib,"Ws2_32.lib")
#include<Winsock2.h>
#include<ws2tcpip.h>
#else
#include"win.h" // port from windows
#endif

#include<stdio.h>
#include<time.h>
#include<stdlib.h>

#include"jhlib.h" // slim version of jh library


// connection info for xpt
typedef struct  
{
	char* ip;
	uint16 port;
	char* authUser;
	char* authPass;
}generalRequestTarget_t;

#include"xptServer.h"
#include"xptClient.h"

// sha256
#ifdef USE_ASM
#include "sha.h"
#define sha256_ctx sha256_state
#define sha256_init sha256_ssse3_init
#define sha256_update sha256_ssse3_update
#define sha256_final sha256_ssse3_final
#elif USE_SPH
#include "sph_sha2.h"
#define sha256_ctx sph_sha256_context
#define sha256_init sph_sha256_init
#define sha256_update sph_sha256
#define sha256_final sph_sha256_close
#elif USE_OPENSSL
#include <openssl/sha.h>
#define sha256_ctx SHA256_CTX
#define sha256_init SHA256_Init
#define sha256_update SHA256_Update
#define sha256_final(x, y) SHA256_Final(y, x)
#else
#include "sha2.h"
#endif

// sha512 
#ifdef USE_ASM
#include "sha512.h"
#define sha512_ctx SHA512_Context
#define sha512_init(x) SHA512_Init(x);
#define sha512_update SHA512_Update
#define sha512_final(x, y) SHA512_Final(x, y)
#define sha512_update_final(x, y, z, w) { SHA512_Update(x, y, z); SHA512_Final(x, w); }
#elif USE_SPH
#define sha512_ctx sph_sha512_context
#define sha512_init sph_sha512_init
#define sha512_update sph_sha512
#define sha512_final sph_sha512_close
#define sha512_update_final sph_sha512_update_final
#elif USE_OPENSSL
#define sha512_ctx SHA512_CTX
#define sha512_init SHA512_Init
#define sha512_update SHA512_Update
#define sha512_final(x, y) SHA512_Final(y, x)
#define sha512_update_final(x, y, z, w) { SHA512_Update(x, y, z); SHA512_Final(w, x); }
#endif

#include"transaction.h"

// global settings for miner
typedef struct  
{
	generalRequestTarget_t requestTarget;
	uint32 protoshareMemoryMode;
}minerSettings_t;

extern minerSettings_t minerSettings;

#define PROTOSHARE_MEM_4096		(0)
#define PROTOSHARE_MEM_2048		(1)
#define PROTOSHARE_MEM_1024		(2)
#define PROTOSHARE_MEM_512		(3)
#define PROTOSHARE_MEM_256		(4)
#define PROTOSHARE_MEM_128		(5)
#define PROTOSHARE_MEM_32		(6)
#define PROTOSHARE_MEM_8		(7)

// block data struct

typedef struct  
{
	// block header data (relevant for midhash)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// birthday collision
	uint32	birthdayA;
	uint32	birthdayB;
	uint32	uniqueMerkleSeed;

	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerProtosharesBlock_t;

#include"algorithm.h"

void jhProtominer_submitShare(minerProtosharesBlock_t* block);

// stats
extern volatile uint32 totalCollisionCount;
extern volatile uint32 totalShareCount;
extern volatile uint32 false_positives;
extern volatile uint32 numSha256Runs;
extern volatile uint32 numSha512Runs;
extern volatile uint32 valid_shares;
extern volatile uint32 invalid_shares;

extern volatile uint32 monitorCurrentBlockHeight;
