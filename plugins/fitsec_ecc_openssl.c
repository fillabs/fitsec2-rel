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
//#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
//#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <assert.h>
#include <inttypes.h>

#include "fitsec_ecc_plugin.h"
#include <string.h>

#include "cserialize.h"
#include "cmem.h"
/*
#if defined(WIN32) && !defined(FITSEC_EXPORT)
#ifdef LIBFITSEC_EXPORTS
#define FITSEC_EXPORT __declspec(dllexport)
#else
#define FITSEC_EXPORT __declspec(dllimport)
#endif
#else
#define FITSEC_EXPORT
#endif
*/
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define EC_POINT_get_affine_coordinates EC_POINT_get_affine_coordinates_GFp
#define EC_POINT_set_affine_coordinates EC_POINT_set_affine_coordinates_GFp
#define EC_POINT_set_compressed_coordinates EC_POINT_set_compressed_coordinates_GFp
static HMAC_CTX * HMAC_CTX_new() {
    HMAC_CTX * c = malloc(sizeof(HMAC_CTX));
    HMAC_CTX_init(c);
    return c;
}
static void HMAC_CTX_free(HMAC_CTX * c) {
    HMAC_CTX_cleanup(c);
    free(c);
}
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

typedef struct {
    FSEccEngine e;
    EC_GROUP * groups[FSCryptCurveId_Max];
    HMAC_CTX * hmac_ctx;
}OpenSSLEccEngine;

static	bool    OpenSSL_InitEngine (OpenSSLEccEngine * e, const char * param);
static	size_t  OpenSSL_Random     (OpenSSLEccEngine * e, void* buf, size_t len);

static FSPrivateKey*   OpenSSL_NewPrivateKey   (OpenSSLEccEngine* c, FSCryptCurveName curve, const uint8_t * data, size_t length);
static bool            OpenSSL_GenerateKeyPair (OpenSSLEccEngine* c, FSCryptCurveName curve,
                                                FSPrivateKey** pPrivateKey, FSPublicKey * publicKey);
static void            OpenSSL_FreePrivateKey  (OpenSSLEccEngine* c, FSPrivateKey* k);
static void            OpenSSL_FreePublicKey  (OpenSSLEccEngine* c, FSPublicKey* k);

static bool            OpenSSL_Calculate       (OpenSSLEccEngine* c, FSCryptCurveName curve, 
                                                const FSPrivateKey* k, FSPublicKey * publicKey);
static size_t          OpenSSL_DeriveKey       (OpenSSLEccEngine* c, const FSPublicKey* k, const FSPrivateKey* eph,
                                                const void* salt, size_t salt_len,
                                                void* digest, size_t digest_len);

static bool  OpenSSL_Sign    (OpenSSLEccEngine * e, const FSPrivateKey * k,
                            FSSignature * s, const uint8_t * digest);
static bool  OpenSSL_Verify  (OpenSSLEccEngine * e, const FSPublicKey * pk,
                            const FSSignature * s, const uint8_t * digest);



static size_t OpenSSL_SymmEncrypt     (FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                       const uint8_t * key, const uint8_t * nonce,
                                       const uint8_t* in_buf,  size_t in_size,
                                       uint8_t* out_buf, size_t out_size);

static size_t OpenSSL_SymmDecrypt     (FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                       const uint8_t* key, const uint8_t* nonce,
                                       const uint8_t* in_buf, size_t in_size,
                                       uint8_t* out_buf, size_t out_size);

static size_t OpenSSL_MAC (FSEccEngine* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out);
static size_t OpenSSL_HMAC(FSEccEngine* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out);

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#elif defined(_MSC_VER)
#pragma warning(disable:4028)
#endif
static FSEccKeyOps _keyOps = {
    OpenSSL_NewPrivateKey,
    OpenSSL_GenerateKeyPair,
    OpenSSL_FreePrivateKey,
    OpenSSL_FreePublicKey,
    OpenSSL_Calculate,
    OpenSSL_DeriveKey
};

static const FSSignatureOps _signOps = {
    OpenSSL_Sign, OpenSSL_Verify
};

static const FSCryptSymmOps _symmOps = {
	OpenSSL_SymmEncrypt,
	OpenSSL_SymmDecrypt

};

static FSMACOps _macOps = {
    OpenSSL_MAC
};


static OpenSSLEccEngine _e = {
    {
        NULL, "openssl", "Open SSL ECC Engine",
        (FSEccEngine_Init_Fn*)OpenSSL_InitEngine,
        &_signOps,
        &_keyOps,
        &_symmOps,
        & _macOps,
        (FS_Random_Fn*)OpenSSL_Random
    }
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(default:4028)
#endif

__INITIALIZER__(OpenSSL_Ecc_Initialize) {
    FSEccEngine_Register(&_e.e);
}

static int _nids[FSCryptCurveId_Max] = {
    NID_X9_62_prime256v1,
    NID_brainpoolP256r1,
    NID_brainpoolP384r1,
};

static int _field_size[FSCryptCurveId_Max] = {32, 32, 48};

static int BN_bn2bin_a(const BIGNUM *a, uint8_t *to, size_t fsize)
{
    size_t bcount = BN_num_bytes(a);
    for(; bcount < fsize; bcount++)
        *(to++) = 0; // add padding with zeros
    return BN_bn2bin(a, to);
}

static	bool    OpenSSL_InitEngine (OpenSSLEccEngine * e,  const char * param)
{
    int i;
    for (i = 0; i < FSCryptCurveId_Max; i++){
        if(i > 0 && _nids[i] == _nids[i-1]) 
            e->groups[i] = e->groups[i-1];
        else
            e->groups[i] = EC_GROUP_new_by_curve_name(_nids[i]);
    }

    e->hmac_ctx = HMAC_CTX_new();
    e->e.Init = NULL; // singletone
    return true;
}

static FSPrivateKey*   OpenSSL_NewPrivateKey   (OpenSSLEccEngine* e, FSCryptCurveName curve, const uint8_t * data, size_t length)
{
    EC_KEY* k;
    const EC_GROUP* group = e->groups[curve];

    k = EC_KEY_new();
    EC_KEY_set_group(k, group);
    if(data){
        BIGNUM * bn = BN_new();
        BN_bin2bn(data, (int)length, bn);

        if(!EC_KEY_set_private_key(k, bn)){
            EC_KEY_free(k);
            k = NULL;
        }
        BN_clear_free(bn);
    }
    return (FSPrivateKey*)k;
}

static void OpenSSL_FreePrivateKey  (OpenSSLEccEngine* c, FSPrivateKey* k) {
    EC_KEY_free((EC_KEY*)k);
}

static void OpenSSL_FreePublicKey  (OpenSSLEccEngine* c, FSPublicKey* k) {
    if(k->k){
        EC_KEY_free((EC_KEY*)k->k);
        k->k = NULL;
    }
}

static bool            OpenSSL_GenerateKeyPair (OpenSSLEccEngine* e, FSCryptCurveName curve,
                                                FSPrivateKey** pPrivateKey, FSPublicKey * publicKey)
{
    bool ret = false;
    const EC_GROUP* g = e->groups[curve];
    int fsize = _field_size[curve];
    EC_KEY* k = NULL;
    if (g) {
        k = EC_KEY_new();
        EC_KEY_set_group(k, g);
        if ((ret = EC_KEY_generate_key(k))) {
            if(publicKey){
                if (publicKey->k) {
                    EC_KEY_free(publicKey->k);
                    publicKey->k = NULL;
                }
                const EC_POINT* p = EC_KEY_get0_public_key(k);
                if (p) {
                    BIGNUM* x = BN_new();
                    BIGNUM* y = BN_new();
                    EC_POINT_get_affine_coordinates(g, p, x, y, NULL);
                    BN_bn2binpad(x, publicKey->point.x, fsize);
                    if (publicKey->point.type == FS_UNCOMPRESSED && publicKey->point.y) {
                        BN_bn2binpad(y, publicKey->point.y, fsize);
                    }
                    else {
                        publicKey->point.type = BN_is_odd(y) ? FS_COMPRESSED_LSB_Y_1 : FS_COMPRESSED_LSB_Y_1;
                    }

                    BN_free(x);
                    BN_free(y);
                    EC_KEY_up_ref(k);
                    publicKey->k = k;
                }
            }
        }
        if (pPrivateKey) {
            (*pPrivateKey) = (FSPrivateKey*)k;
        }
        else {
            EC_KEY_free(k);
        }
    }
    return ret;
}

static EC_KEY* _initPublicKey(OpenSSLEccEngine* e, const FSPublicKey* pk) {
    EC_KEY* k;
    int fsize = _field_size[pk->curve];
    if (pk->k) {
        k = (EC_KEY*)pk->k;
        const EC_POINT* p = EC_KEY_get0_public_key(k);
        if (p)
            return k;
    }

    const EC_GROUP* g = e->groups[pk->curve];
    EC_POINT* pnt = EC_POINT_new(g);
    if (NULL == pnt) {
        return NULL;
    }
    BIGNUM* bnx, * bny;
    bnx = BN_new(); BN_bin2bn(pk->point.x, fsize, bnx);
    if (pk->point.type == FS_UNCOMPRESSED) {
        bny = BN_new(); BN_bin2bn(pk->point.y, fsize, bny);
        EC_POINT_set_affine_coordinates(g, pnt, bnx, bny, NULL);
        BN_clear_free(bny);
    }
    else {
        EC_POINT_set_compressed_coordinates(g, pnt, bnx, pk->point.type & 1, NULL);
    }
    BN_clear_free(bnx);
    k = EC_KEY_new();
    EC_KEY_set_group(k, g);
    if (!EC_KEY_set_public_key(k, pnt)) {
        EC_KEY_free(k); k = NULL;
        EC_POINT_free(pnt);
        return false;
    }
    EC_POINT_free(pnt);
    ((FSPublicKey*)pk)->k = k;
    return k;
}

static bool  OpenSSL_Verify  (OpenSSLEccEngine * e, const FSPublicKey * pk,
                            const FSSignature * s, const uint8_t * digest)
{
    EC_KEY* k = _initPublicKey(e, pk);
    int fsize = _field_size[pk->curve];

    ECDSA_SIG * sg = ECDSA_SIG_new();
    ECDSA_SIG_set0(sg,
        BN_bin2bn(s->point.x, fsize, NULL),
        BN_bin2bn(s->s, fsize, NULL)
    );
    
    int rc = ECDSA_do_verify(digest, fsize, sg, k);
    ECDSA_SIG_free(sg);
    return (rc > 0);
}

static bool  OpenSSL_Sign    (OpenSSLEccEngine * e, const FSPrivateKey * pk,
                            FSSignature * s, const uint8_t * digest)
{
    EC_KEY * k = (EC_KEY *)pk;
    const EC_GROUP* g = EC_KEY_get0_group((const EC_KEY*)k);
    if (g) {
        int fsize = (EC_GROUP_get_degree(g) + 7) / 8;
        ECDSA_SIG * sg = ECDSA_do_sign(digest, fsize, k);
        if(sg){
            const BIGNUM *br = NULL;
            const BIGNUM *bs = NULL;
            ECDSA_SIG_get0(sg, &br, &bs);
            BN_bn2bin_a(br, s->point.x, fsize);
            BN_bn2bin_a(bs, s->s, fsize);
            s->point.type = FS_X_COORDINATE_ONLY;
            ECDSA_SIG_free(sg);
            return true;
        }
    }
    return false;
}

static size_t OpenSSL_KDF2(uint8_t* digest, size_t d_len, const uint8_t* ss, size_t ss_len, const uint8_t* salt, size_t salt_len)
{
    size_t num_blk_out = (d_len + 31) / 32;
    SHA256_CTX h;
    for (size_t i = 1; i < num_blk_out + 1; i++) {
        SHA256_Init(&h);
        SHA256_Update(&h, ss, ss_len);

        uint32_t n = cint32_hton((uint32_t)i);
        SHA256_Update(&h, &n, 4);

        if (salt && salt_len)
            SHA256_Update(&h, salt, salt_len);

        if (i * 32 > d_len) {
            uint8_t out[32];
            SHA256_Final(out, &h);
            memcpy(digest + (i - 1) * 32, out, d_len - (i - 1) * 32);
        }
        else {
            SHA256_Final(digest + (i - 1) * 32, &h);
        }
    }
    return d_len;
}

static size_t          OpenSSL_DeriveKey       (OpenSSLEccEngine* c, const FSPublicKey* pub, const FSPrivateKey* priv,
                                                const void* salt, size_t salt_len,
                                                void* digest, size_t digest_len)
{
    unsigned char ss[64];

    EC_KEY* ek = _initPublicKey(c, pub);
    const EC_POINT * ep = EC_KEY_get0_public_key(ek);

    int l = ECDH_compute_key(ss, sizeof(ss), ep, (EC_KEY*)priv, NULL);

    // KDF2:
    return OpenSSL_KDF2(digest, digest_len, ss, l, salt, salt_len);
}

static void BN_to_bin(const BIGNUM* bn, unsigned char* p, int fsize)
{
    int bcount = BN_num_bytes(bn);
    for (; bcount < fsize; bcount++)
        *(p++) = 0; // add padding with zeros
    BN_bn2bin(bn, p);
}

static bool            OpenSSL_Calculate       (OpenSSLEccEngine* e, FSCryptCurveName curve, 
                                                const FSPrivateKey* priv, FSPublicKey * publicKey)
{
    if (publicKey->k) {
        FSKey_CleanPublic(&e->e, publicKey);
    }

    const EC_GROUP* g = EC_KEY_get0_group((const EC_KEY*)priv);
    const EC_POINT* p = EC_KEY_get0_public_key((const EC_KEY*)priv);
    if (p == NULL) {
        const BIGNUM* k = EC_KEY_get0_private_key((const EC_KEY*)priv);
        EC_POINT* pt = EC_POINT_new(g);
        if (EC_POINT_mul(g, pt, k, NULL, NULL, NULL)) {
            EC_KEY_set_public_key((EC_KEY*)priv, pt);
            p = EC_KEY_get0_public_key((const EC_KEY*)priv);
        }
        EC_POINT_free(pt);
    }

    BIGNUM* x, * y;
    int fsize = (EC_GROUP_get_degree(g) + 7) / 8;

    x = BN_new(); y = BN_new();
    if (EC_POINT_get_affine_coordinates(g, p, x, y, NULL)) {
        BN_to_bin(x, publicKey->point.x, fsize);
        if (publicKey->point.type == FS_UNCOMPRESSED) {
            if (publicKey->point.y) {
                BN_to_bin(y, publicKey->point.y, fsize);
            }
        }
        else if (publicKey->point.type & 2) {
            publicKey->point.type = FS_COMPRESSED_LSB_Y_0 + (BN_is_odd(y) ? 1 : 0);
        }
    }
    BN_clear_free(x); BN_clear_free(y);
    return true;
}

struct {
    int keySize;
    int nonceSize;
    int tagSize;
    const EVP_CIPHER* (*cipher)(void);
}_FSCryptSymmAlgParams[] = {
    {16, 12, 16, EVP_aes_128_ccm}
};

static size_t OpenSSL_SymmEncrypt     (FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                       const uint8_t * key, const uint8_t * nonce,
                                       const uint8_t* in_buf,  size_t in_size,
                                       uint8_t* out_buf, size_t out_size)
{
    int ret = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, _FSCryptSymmAlgParams[alg].cipher(), NULL, NULL, NULL)) {
        // Set nonce length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, _FSCryptSymmAlgParams[alg].nonceSize, NULL);
        // Set tag length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, _FSCryptSymmAlgParams[alg].tagSize, NULL);
        // Prime the key and nonce
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) {
            if (EVP_EncryptUpdate(ctx, out_buf, &ret, in_buf, (int)in_size)) {
                // Finalize the encryption session
                int n = 0;
                if(EVP_EncryptFinal_ex(ctx, out_buf + ret, &n))
                    ret += n;
                // Get the authentication tag at the end of the encrypted text
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, _FSCryptSymmAlgParams[alg].tagSize, out_buf + ret);
                ret += _FSCryptSymmAlgParams[alg].tagSize;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;

}

static size_t OpenSSL_SymmDecrypt     (FSEccEngine* e, FSCryptSymmAlgorithm alg,
                                       const uint8_t* key, const uint8_t* nonce,
                                       const uint8_t* in_buf, size_t in_size,
                                       uint8_t* out_buf, size_t out_size)
{
    int len = 0;
    const uint8_t* tag = in_buf + in_size - _FSCryptSymmAlgParams[alg].tagSize;
    in_size -= _FSCryptSymmAlgParams[alg].tagSize;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, _FSCryptSymmAlgParams[alg].cipher(), NULL, NULL, NULL)) {
        // Set nonce
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, _FSCryptSymmAlgParams[alg].nonceSize, NULL);
        // Set tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, _FSCryptSymmAlgParams[alg].tagSize, (void*)tag);

        // Specify key and IV
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
            // Decrypt plaintext, verify tag: can only be called once
            if (EVP_DecryptUpdate(ctx, out_buf, &len, in_buf, (int)in_size)) {
                int n = 0;
                if (EVP_DecryptFinal_ex(ctx, out_buf + len, &n))
                    len += n;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return len;

}

static size_t OpenSSL_HMAC(FSEccEngine* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out)
{
    unsigned int olen = 16;
    uint8_t t[32];
    HMAC(EVP_sha256(), key, (int)key_len, data, size, t, &olen);
    memcpy(out, t, 16);
    return 16;
}

typedef size_t(FSMAC_Fn)(FSEccEngine* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out);
static FSMAC_Fn* _mac_fns[] = {
    OpenSSL_HMAC
    //    OpenSSL_CMAC
};

static size_t OpenSSL_MAC(FSEccEngine* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out)
{
    return _mac_fns[alg](e, alg, data, size, key, key_len, out);
}


static	size_t  OpenSSL_Random(OpenSSLEccEngine* e, void* buf, size_t len)
{
    if (1 == RAND_bytes(buf, (int)len)) {
        return len;
    }
    return 0;
}
