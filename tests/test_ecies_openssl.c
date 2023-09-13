#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
static const uint8_t v1[32] =
{ 0x13, 0x84, 0xC3, 0x1D, 0x69, 0x82, 0xD5, 0x2B, 0xCA, 0x3B, 0xED, 0x8A, 0x7E, 0x60, 0xF5, 0x2F,
  0xEC, 0xDA, 0xB4, 0x4E, 0x5C, 0x0E, 0xA1, 0x66, 0x81, 0x5A, 0x81, 0x59, 0xE0, 0x9F, 0xFB, 0x42 };
static const uint8_t V1x[32] =
{ 0xF4, 0x5A, 0x99, 0x13, 0x7B, 0x1B, 0xB2, 0xC1, 0x50, 0xD6, 0xD8, 0xCF, 0x72, 0x92, 0xCA, 0x07,
  0xDA, 0x68, 0xC0, 0x03, 0xDA, 0xA7, 0x66, 0xA9, 0xAF, 0x7F, 0x67, 0xF5, 0xEE, 0x91, 0x68, 0x28 };
static const uint8_t V1y[32] =
{ 0xF6, 0xA2, 0x52, 0x16, 0xF4, 0x4C, 0xB6, 0x4A, 0x96, 0xC2, 0x29, 0xAE, 0x00, 0xB4, 0x79, 0x85,
  0x7B, 0x3B, 0x81, 0xC1, 0x31, 0x9F, 0xB2, 0xAD, 0xF0, 0xE8, 0xDB, 0x26, 0x81, 0x76, 0x97, 0x29 };

static const uint8_t v2[32] =
{ 0xD4, 0x18, 0x76, 0x0F, 0x0C, 0xB2, 0xDC, 0xB8, 0x56, 0xBC, 0x3C, 0x72, 0x17, 0xAD, 0x3A, 0xA3,
  0x6D, 0xB6, 0x74, 0x2A, 0xE1, 0xDB, 0x65, 0x5A, 0x3D, 0x28, 0xDF, 0x88, 0xCB, 0xBF, 0x84, 0xE1 };
static const uint8_t V2x[32] =
{ 0xEE, 0x9C, 0xC7, 0xFB, 0xD9, 0xED, 0xEC, 0xEA, 0x41, 0xF7, 0xC8, 0xBD, 0x25, 0x8E, 0x8D, 0x2E,
  0x98, 0x8E, 0x75, 0xBD, 0x06, 0x9A, 0xDD, 0xCA, 0x1E, 0x5A, 0x38, 0xE5, 0x34, 0xAC, 0x68, 0x18 };
static const uint8_t V2y[32] =
{ 0x5A, 0xE3, 0xC8, 0xD9, 0xFE, 0x0B, 0x1F, 0xC7, 0x43, 0x8F, 0x29, 0x41, 0x7C, 0x24, 0x0F, 0x8B,
  0xF8, 0x1C, 0x35, 0x8E, 0xC1, 0xA4, 0xD0, 0xC6, 0xE9, 0x8D, 0x8E, 0xDB, 0xCC, 0x71, 0x40, 0x17 };

static const uint8_t v4[32] =
{ 0x46, 0x24, 0xA6, 0xF9, 0xF6, 0xBC, 0x6B, 0xD0, 0x88, 0xA7, 0x1E, 0xD9, 0x7B, 0x3A, 0xEE, 0x98,
  0x3B, 0x5C, 0xC2, 0xF5, 0x74, 0xF6, 0x4E, 0x96, 0xA5, 0x31, 0xD2, 0x46, 0x41, 0x37, 0x04, 0x9F };
static const uint8_t V4x[32] =
{ 0x12, 0x1A, 0xA4, 0x95, 0xC6, 0xB2, 0xC0, 0x7A, 0x2B, 0x2D, 0xAE, 0xC3, 0x6B, 0xD2, 0x07, 0xD6,
  0x62, 0x0D, 0x7E, 0x60, 0x81, 0x05, 0x0D, 0xF5, 0xDE, 0x3E, 0x96, 0x96, 0x86, 0x8F, 0xCD, 0xCA };
static const uint8_t V4y[32] =
{ 0x46, 0xC3, 0x1A, 0x1A, 0xBE, 0xA0, 0xBD, 0xDA, 0xAA, 0xAE, 0xFB, 0xBA, 0x3A, 0xFD, 0xBF, 0xF1,
  0xAC, 0x8D, 0x19, 0x6B, 0xC3, 0x13, 0xFC, 0x13, 0x09, 0x26, 0x81, 0x0C, 0x05, 0x50, 0x39, 0x50 };

static const uint8_t k1[16] =
{ 0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74, 0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D };
static const uint8_t k3[16] =
{ 0x68, 0x7E, 0x97, 0x57, 0xDE, 0xBF, 0xD8, 0x7B, 0x0C, 0x26, 0x73, 0x30, 0xC1, 0x83, 0xC7, 0xB6 };

static const uint8_t P1[32] =
{ 0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F, 0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
  0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA, 0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9 };
static const uint8_t P3[32] =
{ 0x05, 0xBE, 0xD5, 0xF8, 0x67, 0xB8, 0x9F, 0x30, 0xFE, 0x55, 0x52, 0xDF, 0x41, 0x4B, 0x65, 0xB9,
  0xDD, 0x40, 0x73, 0xFC, 0x38, 0x5D, 0x14, 0x92, 0x1C, 0x64, 0x1A, 0x14, 0x5A, 0xA1, 0x20, 0x51 };

static const uint8_t r1[32] =
{ 0x06, 0x0E, 0x41, 0x44, 0x0A, 0x4E, 0x35, 0x15, 0x4C, 0xA0, 0xEF, 0xCB, 0x52, 0x41, 0x21, 0x45,
  0x83, 0x6A, 0xD0, 0x32, 0x83, 0x3E, 0x6B, 0xC7, 0x81, 0xE5, 0x33, 0xBF, 0x14, 0x85, 0x10, 0x85 };
static const uint8_t R1x[32] =
{ 0x8C, 0x5E, 0x20, 0xFE, 0x31, 0x93, 0x5F, 0x6F, 0xA6, 0x82, 0xA1, 0xF6, 0xD4, 0x6E, 0x44, 0x68,
  0x53, 0x4F, 0xFE, 0xA1, 0xA6, 0x98, 0xB1, 0x4B, 0x0B, 0x12, 0x51, 0x3E, 0xED, 0x8D, 0xEB, 0x11 };
static const uint8_t R1y[32] =
{ 0x12, 0x70, 0xFE, 0xC2, 0x42, 0x7E, 0x6A, 0x15, 0x4D, 0xFC, 0xAE, 0x33, 0x68, 0x58, 0x43, 0x96,
  0xC8, 0x25, 0x1A, 0x04, 0xE2, 0xAE, 0x7D, 0x87, 0xB0, 0x16, 0xFF, 0x65, 0xD2, 0x2D, 0x6F, 0x9E };

static const uint8_t r3[32] =
{ 0xDA, 0x5E, 0x1D, 0x85, 0x3F, 0xCC, 0x5D, 0x0C, 0x16, 0x2A, 0x24, 0x5B, 0x9F, 0x29, 0xD3, 0x8E,
  0xB6, 0x05, 0x9F, 0x0D, 0xB1, 0x72, 0xFB, 0x7F, 0xDA, 0x66, 0x63, 0xB9, 0x25, 0xE8, 0xC7, 0x44 };
static const uint8_t R3x[32] =
{ 0x80, 0x08, 0xB0, 0x6F, 0xC4, 0xC9, 0xF9, 0x85, 0x60, 0x48, 0xDA, 0x18, 0x6E, 0x7D, 0xC3, 0x90,
  0x96, 0x3D, 0x6A, 0x42, 0x4E, 0x80, 0xB2, 0x74, 0xFB, 0x75, 0xD1, 0x21, 0x88, 0xD7, 0xD7, 0x3F };
static const uint8_t R3y[32] =
{ 0x27, 0x74, 0xFB, 0x96, 0x00, 0xF2, 0x7D, 0x7B, 0x3B, 0xBB, 0x2F, 0x7F, 0xCD, 0x8D, 0x2C, 0x96,
  0xD4, 0x61, 0x9E, 0xF9, 0xB4, 0x69, 0x2C, 0x6A, 0x7C, 0x57, 0x33, 0xB5, 0xBA, 0xC8, 0xB2, 0x7D };

static const uint8_t C1[16] =
{ 0xA6, 0x34, 0x20, 0x13, 0xD6, 0x23, 0xAD, 0x6C, 0x5F, 0x68, 0x82, 0x46, 0x96, 0x73, 0xAE, 0x33 };
static const uint8_t C2[16] =
{ 0xDD, 0x53, 0x0B, 0xE3, 0xBC, 0xD1, 0x49, 0xE8, 0x81, 0xE0, 0x9F, 0x06, 0xE1, 0x60, 0xF5, 0xA0 };
static const uint8_t C3[16] =
{ 0x1F, 0x63, 0x46, 0xED, 0xAE, 0xAF, 0x57, 0x56, 0x1F, 0xC9, 0x60, 0x4F, 0xEB, 0xEF, 0xF4, 0x4E };
static const uint8_t C4[16] =
{ 0x6C, 0xFD, 0x13, 0xB7, 0x64, 0x36, 0xCD, 0x0D, 0xB7, 0x02, 0x44, 0xFA, 0xE3, 0x80, 0xCB, 0xA1 };

static const uint8_t T1[16] =
{ 0x80, 0xE1, 0xD8, 0x5D, 0x30, 0xF1, 0xBA, 0xE4, 0xEC, 0xF1, 0xA5, 0x34, 0xA8, 0x9A, 0x07, 0x86 };
static const uint8_t T2[16] =
{ 0x06, 0xC1, 0xF0, 0xF5, 0xEA, 0xED, 0x45, 0x3C, 0xAF, 0x78, 0xE0, 0x1A, 0x3D, 0x16, 0xA0, 0x01 };
static const uint8_t T3[16] =
{ 0x37, 0x3C, 0x0F, 0xA7, 0xC5, 0x2A, 0x07, 0x98, 0xEC, 0x36, 0xEA, 0xDF, 0xE3, 0x87, 0xC3, 0xEF };
static const uint8_t T4[16] =
{ 0xC8, 0xBF, 0x18, 0xAC, 0x79, 0x6B, 0x0B, 0x1D, 0x3A, 0x12, 0x56, 0xD3, 0xA9, 0x16, 0x76, 0xC8 };

const uint8_t k5[16] = {
    0x40, 0xEB, 0xB3, 0xEB, 0x94, 0x21, 0x20, 0xAB, 0x51, 0x74, 0xCE, 0x41, 0xC9, 0x8C, 0x8A, 0xC0 };
const uint8_t v5[32] = {
    0x39, 0xFB, 0x31, 0x6C, 0x5D, 0xE7, 0x8C, 0x16, 0x08, 0xCB, 0x09, 0xAC, 0x24, 0x71, 0xAD, 0x36,
    0x91, 0xB2, 0x20, 0x91, 0x95, 0x11, 0xCF, 0x5F, 0xE6, 0x88, 0x3D, 0x98, 0x23, 0xE8, 0x94, 0x5C };
const uint8_t V5x[32] = {
    0x58, 0xA8, 0xC1, 0x6B, 0x2A, 0x48, 0xCF, 0xEA, 0x9C, 0xA2, 0x8F, 0xE2, 0x31, 0xF2, 0xB6, 0xAC,
    0xFD, 0x22, 0x93, 0xF1, 0x82, 0x28, 0x48, 0x12, 0x92, 0xBB, 0x32, 0xBC, 0xFF, 0x3D, 0x64, 0x87 };
const uint8_t V5y[32] = {
    0x48, 0xF7, 0xEA, 0x04, 0x20, 0x3D, 0x6F, 0x1E, 0x75, 0x0A, 0x6A, 0x25, 0x91, 0x27, 0xC6, 0x94,
    0xFD, 0xFA, 0xCD, 0x50, 0x5F, 0x12, 0x17, 0xB5, 0xE1, 0x7C, 0xA9, 0xD8, 0x7E, 0x7F, 0x2D, 0x18 };
const uint8_t C5[16] = {
    0x35, 0x12, 0x17, 0x0E, 0x04, 0x49, 0xBC, 0x55, 0xE0, 0xDD, 0x75, 0x01, 0xC2, 0x0E, 0x99, 0xB8 };
const uint8_t T5[16] = {
    0x5E, 0x15, 0x9C, 0x27, 0x51, 0xEE, 0xE4, 0xB5, 0x1A, 0x56, 0x78, 0xD0, 0x4E, 0xA3, 0x6D, 0x3C };
const uint8_t r5[32] = {
    0xF4, 0xF7, 0xA4, 0x88, 0x14, 0x48, 0x03, 0x6D, 0xFC, 0xA6, 0xA4, 0x0D, 0xB4, 0x29, 0x13, 0xCD,
    0xC0, 0x9D, 0x17, 0xAA, 0xCB, 0xC0, 0x02, 0x8D, 0x5F, 0x81, 0xDE, 0x79, 0x29, 0x59, 0x76, 0xD2 };
const uint8_t R5x[32] = {
    0x05, 0x42, 0xFF, 0x28, 0xF6, 0x64, 0x86, 0xC4, 0xAF, 0x18, 0xEB, 0xC5, 0x60, 0xD9, 0x10, 0x83,
    0x87, 0x1C, 0x24, 0x33, 0x1B, 0x89, 0x19, 0x85, 0xE9, 0x2E, 0xCE, 0xC8, 0xC9, 0x8C, 0xAD, 0xE9 };
const uint8_t R5y[32] = {
    0x39, 0x65, 0x34, 0xF1, 0x8A, 0x71, 0x11, 0x1A, 0x4E, 0xB4, 0xDE, 0x53, 0xFA, 0x26, 0xA7, 0x23,
    0x20, 0x75, 0x91, 0x5E, 0x89, 0xC0, 0x7D, 0xAB, 0x88, 0x30, 0x5C, 0x39, 0x34, 0x52, 0x7B, 0x49 };
const uint8_t P5[32] = {
    0x06, 0xB8, 0xAC, 0xCA, 0xB6, 0x68, 0x84, 0x62, 0x2F, 0x34, 0x56, 0x8A, 0xDF, 0x2C, 0xE2, 0xD2,
    0x57, 0x1D, 0x99, 0xD5, 0x00, 0x15, 0xED, 0x51, 0x75, 0x69, 0x09, 0xBD, 0x25, 0x3D, 0x4C, 0xA2 };

const uint8_t k6[16] = {
    0x68, 0x10, 0x4E, 0xD3, 0x39, 0x4F, 0xD4, 0xE9, 0x03, 0x89, 0xA0, 0x85, 0x59, 0x7E, 0x47, 0x91 };
const uint8_t v6[32] = {
    0xB2, 0xD0, 0xF3, 0x1F, 0xC9, 0xE9, 0x27, 0xDD, 0x1E, 0xB5, 0x29, 0xFB, 0xF3, 0x0A, 0xB6, 0xB8,
    0x32, 0x72, 0x63, 0xD9, 0x23, 0x81, 0xA5, 0x8F, 0x03, 0xD6, 0x96, 0xDE, 0x3F, 0x12, 0xCB, 0xAA };
const uint8_t V6x[32] = {
    0x8C, 0xCE, 0xE1, 0x14, 0x0B, 0x56, 0xED, 0x1A, 0xC5, 0xB0, 0x21, 0x97, 0x01, 0x2D, 0xDE, 0x7E,
    0x04, 0xEF, 0x9A, 0xAC, 0xDC, 0x31, 0xF7, 0x7C, 0xF5, 0x5F, 0x7D, 0x24, 0x5E, 0x96, 0x2F, 0x3D };
const uint8_t V6y[32] = {
    0x7D, 0xB5, 0x91, 0x97, 0x59, 0xEA, 0x47, 0xC1, 0x60, 0x2D, 0x27, 0x16, 0xC8, 0xC7, 0x0B, 0x8E,
    0x14, 0x55, 0xEE, 0xA1, 0x08, 0x0C, 0x39, 0xD5, 0xF1, 0x0E, 0x54, 0xDD, 0xE6, 0x66, 0xF4, 0x3E };
const uint8_t C6[16] = {
    0x7C, 0x10, 0xA9, 0x9E, 0xE6, 0xC9, 0x18, 0x38, 0x72, 0x09, 0xBD, 0xAA, 0xD4, 0xB2, 0xDD, 0xC6 };
const uint8_t T6[16] = {
    0xC3, 0x06, 0x31, 0xAB, 0x60, 0xD1, 0x16, 0xA2, 0xCA, 0x4F, 0xBE, 0xC9, 0x7C, 0x71, 0x18, 0x24 };

typedef struct {
    const uint8_t* v;  // Sender�s ephemeral private key
    const uint8_t* Vx; // Sender�s ephemeral public key X
    const uint8_t* Vy; // Sender�s ephemeral public key Y
    const uint8_t* k;  // AES key to be encrypted [16 bytes]
    const uint8_t* p1; // Hash(RecipientInfo) [16 bytes]
    const uint8_t* r;  // Recipient�s private key (decryption input)
    const uint8_t* Rx; // Recipient�s public key X
    const uint8_t* Ry; // Recipient�s public key Y
    const uint8_t* C;  // Encrypted (wrapped) AES key
    const uint8_t* T;  // Authentication tag
}EciesVector;

static const EciesVector _eciesVectors[] = {
    {&v1[0], &V1x[0], &V1y[0], &k1[0], &P1[0], &r1[0], &R1x[0], &R1y[0], &C1[0], &T1[0]},
    {&v2[0], &V2x[0], &V2y[0], &k1[0], &P1[0], &r1[0], &R1x[0], &R1y[0], &C2[0], &T2[0]},
    {&v1[0], &V1x[0], &V1y[0], &k3[0], &P3[0], &r3[0], &R3x[0], &R3y[0], &C3[0], &T3[0]},
    {&v4[0], &V4x[0], &V4y[0], &k3[0], &P3[0], &r3[0], &R3x[0], &R3y[0], &C4[0], &T4[0]},
    {&v5[0], &V5x[0], &V5y[0], &k5[0], &P5[0], &r5[0], &R5x[0], &R5y[0], &C5[0], &T5[0]},
    {&v6[0], &V6x[0], &V6y[0], &k6[0], &P5[0], &r5[0], &R5x[0], &R5y[0], &C6[0], &T6[0]}
};

EC_KEY* create_key(const uint8_t* priv)
{
    EC_KEY* key;

    if ((key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
        BIGNUM* bn = BN_new();
        BN_bin2bn(priv, 32, bn);
        EC_KEY_set_private_key(key, bn);

        const EC_GROUP* g = EC_KEY_get0_group(key);
        EC_POINT* pt = EC_POINT_new(g);
        if (pt) {
            if (EC_POINT_mul(g, pt, bn, NULL, NULL, NULL)) {
                EC_KEY_set_public_key(key, pt);
                EC_POINT_free(pt);
                BN_free(bn);
                return key;
            }
            EC_POINT_free(pt);
        }
        EC_KEY_free(key);
    }
    return NULL;
}

size_t get_secret(EC_KEY* key, const EC_POINT* peer_pub_key, uint8_t * out)
{
    int field_size, slen;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    slen = (field_size + 7) / 8;
    return ECDH_compute_key(out, slen, peer_pub_key, key, NULL);
}

int main(int argc, char* argv[])
{
    for (int i = 0; i < sizeof(_eciesVectors) / sizeof(_eciesVectors[0]); i++) {
        const EciesVector* v = &_eciesVectors[i];
        EC_KEY* alice = create_key(v->v);
        EC_KEY* bob = create_key(v->r);

        const EC_POINT* alice_public = EC_KEY_get0_public_key(alice);
        const EC_POINT* bob_public = EC_KEY_get0_public_key(bob);

        uint8_t alice_secret[256];
        uint8_t bob_secret[256];

        size_t alice_secret_len = get_secret(alice, bob_public, alice_secret);
        size_t bob_secret_len = get_secret(bob, alice_public, bob_secret);
        assert(alice_secret_len == bob_secret_len);

        assert(0 == memcmp(alice_secret, bob_secret, alice_secret_len));

        EC_KEY_free(alice);
        EC_KEY_free(bob);

    }
    return 0;
}
