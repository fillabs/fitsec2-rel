#ifndef _FITSEC_PKI_H_
#define _FITSEC_PKI_H_
#include "fitsec.h"
#include "fitsec_geometry.h"
#include "fitsec_time.h"

#define FS_PKI_VERSION     1
#define FS_PKI_VERSION_CTL 1
#define FS_PKI_VERSION_CRL 1

#define FS_CTL_SSP_TLM 0x80
#define FS_CTL_SSP_RCA 0x40
#define FS_CTL_SSP_EA  0x20
#define FS_CTL_SSP_AA  0x10
#define FS_CTL_SSP_DC  0x08

#define FS_CREQ_SSP_ENR_REQ   0x80
#define FS_CREQ_SSP_AUTH_REQ  0x40
#define FS_CREQ_SSP_VAL_REQ   0x20
#define FS_CREQ_SSP_AUTH_RES  0x10
#define FS_CREQ_SSP_VAL_RES   0x08
#define FS_CREQ_SSP_ENR_RES   0x04
#define FS_CREQ_SSP_CA_REQ    0x02

#define DEFAULT_REQ_STORAGE_DURATION 30 // 30 sec is more than enough
#ifdef __cplusplus
extern "C" {
#endif

    typedef struct FitSecPkiConfig {
        struct {
            const uint8_t * id;
            size_t          id_len;
            FSCurve         alg;
            const uint8_t * priv;
        }station;
        uint32_t            reqStorageDuration;
    } FitSecPkiConfig;

    typedef struct FitSecPki {
        FitSec * e;
        const FitSecPkiConfig * cfg;
    }FitSecPki;

    FITSEC_EXPORT FitSecPki * FitSecPki_New(FitSec * e, const FitSecPkiConfig * cfg);
    FITSEC_EXPORT void        FitSecPki_Free(FitSecPki * const pki);

/** Load PKI message from the given buffer.
 *  Each PKI message is an IEEE1609Dot2Data signed message containing PKI related payload.
 *  This function parses the IEEE1609Dot2Data, validate the message and and call the  
 *  FitSecPki_loadMessage to perform all necessary actions
 *  @param e       [In]  The engine
 *  @param buf     [In]  The message buffer to be parsed.
 *  @param buflen  [In]  The message buffer length.
 *  @return        error value or 0 siccess
 */
FITSEC_EXPORT int FitSecPki_loadData(FitSecPki* pki, const void* buf, size_t buflen);

/** Apply the already parsed and validated PKI responds.
 *  @param e       [In]  The engine
 *  @param m       [In]  The message information structure been used to parse the PKI message.
 *  @return        error value or 0 siccess
 *
 *  Description of fields in FSMessageInfo:
 *  ---------------|--------------------------------------------
 *  generationTime | in: the current ITS time
 *  payload        | in: points to the payload containing EtsiTs102941Data message
 *  payloadSize    | in: the size of the payload
 *  cert           | in: the certificate been used to sign message
 */
FITSEC_EXPORT bool FitSecPki_loadMessage(FitSecPki* pki, FSMessageInfo* m);

typedef struct FSCertificateParams
{
    FSCurve             vKeyAlg;
    FSCurve             eKeyAlg;
    
    uint32_t            startTime;
    duration_t          durationType;
    uint32_t            duration;
    
    const FSGeoRegion * region;
    
    FSItsAidSsp         appPermissions[16];
    FSItsAidSsp         issuePermissions[16];

}FSCertificateParams;

FITSEC_EXPORT size_t FitSecPki_PrepareATRequest(FitSecPki* param, const FSCertificateParams* params, FSMessageInfo * m);

FITSEC_EXPORT size_t FitSecPki_PrepareECRequest(FitSecPki* pki, const FSCertificateParams * params, FSMessageInfo * m);

#ifdef __cplusplus
}
#endif

#endif
