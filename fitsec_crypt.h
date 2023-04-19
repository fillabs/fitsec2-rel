/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/

#ifndef fitsec_crypt_h
#define fitsec_crypt_h

// for size_t
#include <stddef.h>
#include "fitsec_types.h"
#include "fitsec_hash.h"

#ifdef __cplusplus
extern "C" {
#endif
//    typedef struct FitSec              FitSec;
//    typedef struct FSCryptKey          FSCryptKey;
    typedef struct FSPublicKey         FSPublicKey;
    typedef struct FSPrivateKey        FSPrivateKey;
    typedef struct FSSignature         FSSignature;
    typedef struct FSEccEngine         FSEccEngine;
    typedef struct FSEccPoint          FSEccPoint;
//    typedef struct FSCryptSymm         FSCryptSymm;
//    typedef struct FSCryptSignature    FSCryptSignature;
//    typedef struct FSCryptEngine       FSCryptEngine;
//    typedef struct FSCryptEngineConfig FSCryptEngineConfig;


    typedef enum {
        FS_NISTP256,
        FS_BRAINPOOLP256R1,
        FS_BRAINPOOLP384R1,
        FS_NISTP384,
        FS_SM2,

        FSCryptCurveId_Max
    }FSCryptCurveName;

    typedef enum {
        FS_HMAC256
    }FSMAC;

    typedef enum {
        FS_AES_128_CCM = 0,

        FSCryptSymmAlgorithm_Max
    }FSCryptSymmAlgorithm;

    typedef enum {
        FS_X_COORDINATE_ONLY = 0,
        FS_COMPRESSED_LSB_Y_0 = 2,
        FS_COMPRESSED_LSB_Y_1 = 3,
        FS_UNCOMPRESSED = 4
    }FitSecEccPointType;

    struct FSEccPoint {
        FitSecEccPointType type;
        uint8_t * x;
        uint8_t * y;
    };

    struct FSPublicKey {
        FSCryptCurveName curve;
        FSEccPoint       point;
        void           * k; // for plugin usage
    };

    inline static size_t FSKey_FieldSize(FSCryptCurveName curve) {
        switch(curve){
        case FS_BRAINPOOLP384R1:
        case FS_NISTP384:
            return 48;
        default:
            break;
        }
        return 32;
    }

    FITSEC_EXPORT void FSEccEngine_Init(FSEccEngine* engine, const char * params);

    FITSEC_EXPORT FSPrivateKey*   FSKey_ImportPrivate   (FSEccEngine* e, FSCryptCurveName curve, const uint8_t * data, size_t len);

    FITSEC_EXPORT FSPrivateKey*   FSKey_Generate        (FSEccEngine* e, FSCryptCurveName curve, FSPublicKey * k);

    FITSEC_EXPORT void            FSKey_FreePrivate     (FSEccEngine* e, FSPrivateKey* k);
    FITSEC_EXPORT void            FSKey_CleanPublic     (FSEccEngine* e, FSPublicKey * k);

    FITSEC_EXPORT void            FSKey_InitPublic      (FSPublicKey * k, FSCryptCurveName curve, FitSecEccPointType pType, const uint8_t * x, const uint8_t * y);
    FITSEC_EXPORT bool            FSKey_CalculatePublic (FSEccEngine* e, FSPublicKey * k, FSCryptCurveName curve, const FSPrivateKey * pK);

    FITSEC_EXPORT size_t          FSKey_Derive          (FSEccEngine* e, const FSPublicKey* k, const FSPrivateKey* eph,
                                                         const void* salt, size_t salt_len,
                                                         void* digest, size_t digest_len);

    FITSEC_EXPORT bool            FSKey_ReconstructPublic(FSEccEngine* e, const FSPublicKey* rv, 
                                                         const FSPublicKey* ca, const unsigned char * hash);

    struct FSSignature {
        FSCryptCurveName    curve;
        FSEccPoint          point;
        uint8_t           * s;
    };

    FITSEC_EXPORT bool FSSignature_Sign(FSEccEngine* e, FSSignature * s, const FSPrivateKey* k, const uint8_t * digest);

    FITSEC_EXPORT bool FSSignature_Verify(FSEccEngine* e, const FSSignature * s, const FSPublicKey* pk, const uint8_t * digest);

    FITSEC_EXPORT size_t FSCrypt_MAC(FSEccEngine* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out);

    FITSEC_EXPORT size_t FSSymm_Encrypt(FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                        const uint8_t* key, const uint8_t* nonce,
                                        const uint8_t* in_buf, size_t in_size,
                                        uint8_t* out_buf, size_t out_size);
    FITSEC_EXPORT size_t FSSymm_Decrypt(FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                        const uint8_t* key, const uint8_t* nonce,
                                        const uint8_t* in_buf, size_t in_size,
                                        uint8_t* out_buf, size_t out_size);

    FITSEC_EXPORT void            FS_Random(FSEccEngine* e, void* ptr, size_t const len);


#ifdef __cplusplus
}
#endif
#endif
