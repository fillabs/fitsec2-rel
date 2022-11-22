#ifndef FITSEC_HASH_H
#define FITSEC_HASH_H
#include "fitsec_types.h"
#ifdef __cplusplus
extern "C" {
#endif

    uint8_t* FSCryptHash_Calc(FitSec* e, FSCryptHashAlgorithm alg, const void* data, size_t len, uint8_t* md);

    const uint8_t* FSCryptHash_EmptyString(FSCryptHashAlgorithm alg);

    static inline size_t FSCryptHash_Size(FSCryptHashAlgorithm alg) {
        return (alg == FS_SHA384) ? 48 : 32;
    }

    static inline FSHashedId8 FSCryptHash_Digest(FSCryptHashAlgorithm alg, const uint8_t * hash) {
        return *(FSHashedId8*) (hash + ( (alg == FS_SHA384) ? 48 : 32) - sizeof(FSHashedId8));
    }

#ifdef __cplusplus
}
#endif

#endif
