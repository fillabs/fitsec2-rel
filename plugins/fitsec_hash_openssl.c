/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <assert.h>
#include <inttypes.h>
#include "fitsec_hash_plugin.h"
#include "../src/fitsec_i.h"

#include <string.h>

#include "cserialize.h"

static  bool        OpenSSL_HashInitEngine(FSCryptHashOps* e, const char * params);
static uint8_t*     OpenSSL_HashCalc(FSCryptHashOps* e, FSCryptHashAlgorithm alg, const void* data, size_t len, uint8_t* md);

static FSCryptHashOps _openssh_hash_ops = {
    NULL,
    "openssl",
    "OpenSSL Hash engine supports SHA256 and SHA384",

    OpenSSL_HashInitEngine,
    OpenSSL_HashCalc,
};

__INITIALIZER__(OpenSSL_Hash_Initialize) {
    FSCryptHashOps_Register(&_openssh_hash_ops);
}

/*************************************************************************************************/
typedef struct SHAConfig {
    unsigned char* (*Calc)  (const unsigned char *d, size_t n, unsigned char *md);
}SHAConfig;

static SHAConfig _sha_cfg[FSCryptHashAlgorithm_Max] = {
    {
        SHA256,
    }, {
        SHA384,
    }
};

static	unsigned char *  OpenSSL_HashCalc(FSCryptHashOps* e, FSCryptHashAlgorithm alg, const void * ptr, size_t length, uint8_t* hash) {
    return _sha_cfg[alg].Calc(ptr, length, hash);
}

static bool OpenSSL_HashInitEngine(FSCryptHashOps* e, const char * params)
{
    return true;
}
