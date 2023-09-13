/*********************************************************************
This file is a part of FItsSec project: Implementation of ETSI TS 103 097
Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

This file is NOT a free software and should not be used in any situations
without explicit permissions of the author.
*********************************************************************/

#ifndef fitsec_cert_h
#define fitsec_cert_h

#ifndef FITSEC_EXPORT
# ifdef WIN32
#  ifdef LIBFITSEC_EXPORTS
#   define FITSEC_EXPORT __declspec(dllexport)
#  else
#   define FITSEC_EXPORT __declspec(dllimport)
#  endif
# else
#  define FITSEC_EXPORT
# endif
#endif

#include "fitsec_types.h"
#include "fscrypt.h"

#define MAX_AID_COUNT  16  // maximum 16 AID/SSP items per certificate (FitSec limitation)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG_CERT_ALLOC 
    FITSEC_EXPORT FSCertificate* FSCertificate_New_D(FitSec* e, const char* F, int L);
#   define FSCertificate_New(E) FSCertificate_New_D(E,__FILE__,__LINE__)
    FITSEC_EXPORT void           FSCertificate_Release_D(FSCertificate* c, const char* F, int L);
#   define FSCertificate_Release(C) FSCertificate_Release_D(C,__FILE__,__LINE__)
    FITSEC_EXPORT FSCertificate* FSCertificate_Retain_D(FSCertificate* c, const char* F, int L);
#   define FSCertificate_Retain(C) FSCertificate_Retain_D(C,__FILE__,__LINE__)
    FITSEC_EXPORT FSCertificate* FSCertificate_Assign_D(FSCertificate** p, FSCertificate* c, const char* F, int L);
#   define FSCertificate_Assign(C,S) FSCertificate_Assign_D(C,S,__FILE__,__LINE__)
#else
    FITSEC_EXPORT FSCertificate* FSCertificate_New(FitSec* e);
    FITSEC_EXPORT void           FSCertificate_Release(FSCertificate* c);
    FITSEC_EXPORT FSCertificate* FSCertificate_Retain(FSCertificate* c);
    FITSEC_EXPORT FSCertificate* FSCertificate_Assign(FSCertificate** p, FSCertificate* c);
#endif

    typedef enum {
        FSCERT_LOADED   = 0x01,
        FSCERT_INVALID  = 0x02,
        FSCERT_TRUSTED  = 0x04,
    //    FSCERT_LOCAL    = 0x08,
        FSCERT_REVOKED  = 0x10,
    }FSCertificateState;

    FITSEC_EXPORT uint32_t           FSCertificate_GetState(const FSCertificate* c);
    FITSEC_EXPORT void               FSCertificate_SetState(FSCertificate* c, uint32_t set, uint32_t remove);

    typedef struct FSGeoRegion FSGeoRegion;
    
    FITSEC_EXPORT const FSItsAidSsp* FSCertificate_GetAppPermissions(const FSCertificate* c, FSItsAid aid);

    const FSPublicKey* FSCertificate_GetVerificationKey(const FSCertificate* c);
    const FSPublicKey* FSCertificate_GetEncryptionKey(const FSCertificate* c);
    bool               FSCertificate_SetEncryptionPrivateKey(FSCertificate * c, FSPrivateKey * key);
    bool               FSCertificate_SetVerificationPrivateKey(FSCertificate * c, FSPrivateKey * key);

    // load certificate from the buffer
    // does not perform any validation
    FITSEC_EXPORT size_t         FSCertificate_Load(FSCertificate* c, const char* const ptr, size_t len, int* const perror);
    FN_THROW(RuntimeException)
    FITSEC_EXPORT void           FSCertificate_Read(FSCertificate * c, const char** const ptr, const char* const end, int error);

    // validate the certificate against its signer
    FITSEC_EXPORT bool           FSCertificate_Validate(FSCertificate* c, int * const perror);
    
    // validate the certificate chain until the first occurence of already validated certificate.
    // check the chain for revoked certificates
    FITSEC_EXPORT bool           FSCertificate_ValidateChain(FSCertificate* c, int* error);

    FITSEC_EXPORT bool           FSCertificate_IsValidForTime(const FSCertificate* c, FSTime64 time, int* const perror);
    FITSEC_EXPORT bool           FSCertificate_IsValidForPosition(const FSCertificate* c, const FSLocation* position, int* const perror);
    FITSEC_EXPORT bool           FSCertificate_IsValidForRegion(const FSCertificate* c, const FSGeoRegion* region, int* const perror);
    FITSEC_EXPORT bool           FSCertificate_IsValidForAppSSP(const FSCertificate* c, const FSItsAidSsp* ssp, int* const perror);
    FITSEC_EXPORT bool           FSCertificate_IsValidForIssuingSSP(const FSCertificate * c, const FSItsAidSsp * ssp, int chainLength, int * const perror);
    FITSEC_EXPORT bool           FSCertificate_IsValidFor(const FSCertificate* c, const FSItsAidSsp* ssp, const FSLocation* position, FSTime64 time, int* const perror);

    FITSEC_EXPORT bool           FSCertificate_SetCRLParams(FSCertificate* c, FSTime32 thisUpdate, FSTime32 nextUpdate);
    FITSEC_EXPORT void           FSCertificate_SetDC(FSCertificate* c, const char* url, size_t urllength);
    FITSEC_EXPORT bool           FSCertificate_GetDC(const FSCertificate* c, char ** pUrl, size_t * plen);
    FITSEC_EXPORT bool           FSCertificate_DeleteDC(FSCertificate* c, const char* url, size_t urllength);
    FITSEC_EXPORT bool           FSCertificate_SelectNextDC(FSCertificate* c);

#ifdef __cplusplus
}
#endif
#endif