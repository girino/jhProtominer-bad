/*
 * shaselection.h
 *
 *  Created on: 16/12/2013
 *      Author: girino
 */

#ifndef SHASELECTION_H_
#define SHASELECTION_H_

// sha256
//#ifdef USE_ASM
//#include "sha.h"
//#define sha256_ctx sha256_state
//#define sha256_init sha256_ssse3_init
//#define sha256_update sha256_ssse3_update
//#define sha256_final sha256_ssse3_final
//#elif USE_SPH
//#include "sph_sha2.h"
//#define sha256_ctx sph_sha256_context
//#define sha256_init sph_sha256_init
//#define sha256_update sph_sha256
//#define sha256_final sph_sha256_close
//#elif USE_OPENSSL
//#include <openssl/sha.h>
//#define sha256_ctx SHA256_CTX
//#define sha256_init SHA256_Init
//#define sha256_update SHA256_Update
//#define sha256_final(x, y) SHA256_Final(y, x)
//#else
//#include "sha2.h"
//#endif

// sha512
//#ifdef USE_ASM
//#include "sha512.h"
//#define sha512_ctx SHA512_Context
//#define sha512_init(x) SHA512_Init(x);
//#define sha512_update SHA512_Update
//#define sha512_final(x, y) SHA512_Final(x, y)
//#define sha512_update_final(x, y, z, w) { SHA512_Update(x, y, z); SHA512_Final(x, w); }
//#elif USE_SPH
//#define sha512_ctx sph_sha512_context
//#define sha512_init sph_sha512_init
//#define sha512_update sph_sha512
//#define sha512_final sph_sha512_close
//#define sha512_update_final sph_sha512_update_final
//#elif USE_OPENSSL
//#define sha512_ctx SHA512_CTX
//#define sha512_init SHA512_Init
//#define sha512_update SHA512_Update
//#define sha512_final(x, y) SHA512_Final(y, x)
//#define sha512_update_final(x, y, z, w) { SHA512_Update(x, y, z); SHA512_Final(w, x); }
//#endif



#endif /* SHASELECTION_H_ */
