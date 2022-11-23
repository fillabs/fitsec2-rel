#ifndef FITSEC_HASH_PLUGIN_H
#define FITSEC_HASH_PLUGIN_H
#include "../fitsec_hash.h"
#include "../fitsec_types.h"
#include <cring.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct FSCryptHashOps FSCryptHashOps;

    typedef bool         (FSCryptHashOps_Init_Fn)(FSCryptHashOps * e, const char * params);
    typedef uint8_t*     (FSCryptHash_Calc_Fn)   (FSCryptHashOps * e, FSCryptHashAlgorithm alg, const void* data, size_t len, uint8_t* md);
    struct FSCryptHashOps
    {
        FSCryptHashOps* _next;
        const char* name;
        const char* description;

        FSCryptHashOps_Init_Fn* InitEngine;
        FSCryptHash_Calc_Fn* Calc;
    };

    void FSCryptHashOps_Register(FSCryptHashOps* ops);

    bool FitSec_SelectHashEngine(FitSec* e, const char* name);

#ifdef __cplusplus
}
#endif

#endif
