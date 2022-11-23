#ifndef _FITSEC_PKI_H_
#define _FITSEC_PKI_H_
#include "fitsec.h"

#define FS_PKI_VERSION     1
#define FS_PKI_VERSION_CTL 1
#define FS_PKI_VERSION_CRL 1

#define FS_CTL_SSP_TLM 0x80
#define FS_CTL_SSP_RCA 0x40
#define FS_CTL_SSP_EA  0x20
#define FS_CTL_SSP_AA  0x10
#define FS_CTL_SSP_DC  0x08

#ifdef __cplusplus
extern "C" {
#endif

/** Load PKI message from the given buffer.
 *  Each PKI message is an IEEE1609Dot2Data signed message containing PKI related payload.
 *  This function parses the IEEE1609Dot2Data, validate the message and and call the  
 *  FitSecPki_loadMessage to perform all necessary actions
 *  @param e       [In]  The engine
 *  @param buf     [In]  The message buffer to be parsed.
 *  @param buflen  [In]  The message buffer length.
 *  @return        error value or 0 siccess
 */
FITSEC_EXPORT int FitSecPki_loadData(FitSec* e, const void* buf, size_t buflen);

/** Apply the already parsed and validated PKI message.
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
FITSEC_EXPORT int FitSecPki_loadMessage(FitSec* e, FSMessageInfo* m);

/** Request the CTL or CRL from the given certificate.
 *  This function performs following steps:
 *    1. Checks that the certificate has a permission to sign the CRL or CTL
 *    2. Checks that at least one DC is assigned to the certificate
 *    3. Prepare the CRL/CTL request URL base on certificate DC
 *    4. Call the application callback with the FSEvent_HttpRequest event
 *  Application shall perform the HTTP request and call FitSecPki_loadData with the received data.  
*/
FITSEC_EXPORT int FitSecPki_requestCTL(FitSec* e, const FSCertificate* root);
FITSEC_EXPORT int FitSecPki_requestCRL(FitSec* e, const FSCertificate* root);

#ifdef __cplusplus
}
#endif

#endif
