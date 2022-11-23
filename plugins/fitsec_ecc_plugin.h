#ifndef FITSEC_ECC_PLUGIN_H
#define FITSEC_ECC_PLUGIN_H

#include "../fitsec_crypt.h"
#include "../fitsec_types.h"
#include <cring.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct FSEccEngine  FSEccEngine;
    typedef struct FSPublicKey  FSPublicKey;
    typedef struct FSPrivateKey FSPrivateKey;
    
    typedef struct FSSignature FSSignature;

    typedef bool   (FSEccEngine_Init_Fn)      (FSEccEngine * e, const char * params);
    
    typedef void (FS_Random_Fn)(FSEccEngine * e, void * ptr, size_t length);

    typedef struct {
        bool  (*Sign)    (FSEccEngine * e, const FSPrivateKey * k,
                          FSSignature * s, const uint8_t * digest);
        bool  (*Verify)  (FSEccEngine * e, const FSPublicKey * pk,
                          const FSSignature * s, const uint8_t * digest);
    }FSSignatureOps;

    typedef struct {
        // allocate new private key 
        FSPrivateKey*   (*Import)      (FSEccEngine* c, FSCryptCurveName curve, const uint8_t * data, size_t len);
        bool            (*Generate)    (FSEccEngine* c, FSCryptCurveName curve,
                                        FSPrivateKey** pPrivateKey, FSPublicKey * publicKey);
        void            (*FreePrivate) (FSEccEngine* c, FSPrivateKey* k);
        void            (*FreePublic)  (FSEccEngine* c, FSPublicKey* k);
        bool            (*Calculate)   (FSEccEngine* c, FSCryptCurveName curve, 
                                        const FSPrivateKey* k, FSPublicKey * publicKey);
        size_t          (*Derive)      (FSEccEngine* e,
                                        const FSPublicKey* k, const FSPrivateKey* eph,
                                        const void* salt, size_t salt_len,
                                        void* digest, size_t digest_len);
    }FSEccKeyOps;

    typedef struct FSCryptSymmOps {

        size_t          (*Encrypt)    (FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                       const uint8_t * key, const uint8_t * nonce,
                                       const uint8_t* in_buf,  size_t in_size,
                                       uint8_t* out_buf, size_t out_size);

        size_t          (*Decrypt)    (FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                       const uint8_t* key, const uint8_t* nonce,
                                       const uint8_t* in_buf, size_t in_size,
                                       uint8_t* out_buf, size_t out_size);
    }FSCryptSymmOps;

    typedef struct FSMACOps {
        size_t (*mac)(FSEccEngine * e, FSMAC alg, const uint8_t * data, size_t size, const uint8_t * key, size_t key_len, uint8_t * out);
    }FSMACOps;

    struct FSEccEngine
    {
        FSEccEngine* _next;
        const char* name;
        const char* description;

        FSEccEngine_Init_Fn      * Init;
        const FSSignatureOps     * SignatureOps;
        const FSEccKeyOps        * KeyOps;
        const FSCryptSymmOps     * SymmOps;
        const FSMACOps           * MACOps;
        FS_Random_Fn             * Random;
        // to be extended in plugin
    };

    FITSEC_EXPORT void FSEccEngine_Register(FSEccEngine* e);

    FITSEC_EXPORT FSEccEngine* FitSec_FindEccEngine(const char* name);

#ifdef __cplusplus
}
#endif

#endif
