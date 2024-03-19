/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.4.1,
 * ETSI TS 102 941 v1.4.1
 * Copyright (C) 2022  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/

#ifndef fitsec2_h
#define fitsec2_h

#define FS_VERSION_RELEASE 2
#define FS_VERSION_MAJOR 4
#define FS_VERSION_MINOR 1

/* configuration */
#define FITSEC_HAVE_OPENSSL
#define FITSEC_HAVE_ENCRYPTION
//#define FITSEC_HAVE_PKI


#define FITSEC_AID_CAM     36
#define FITSEC_AID_DENM    37
#define FITSEC_AID_SPATEM  137
#define FITSEC_AID_MAPEM   138
#define FITSEC_AID_IVIM    139
#define FITSEC_AID_TLC     140
#define FITSEC_AID_GNMGMT  141
#define FITSEC_AID_CRT_REQ 623
#define FITSEC_AID_CRL     622
#define FITSEC_AID_CTL     624
#define FITSEC_AID_ANY     -1

#define FS_PERMISSIONS_MAX 16 //max 16 AID permissions per certificate (FitSec limit)

#include "fitsec_types.h"
#include "fitsec_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

    /** Supported payload types */
    typedef enum  {
        FS_PAYLOAD_AUTO = 0,
        FS_PAYLOAD_UNSECURED = 1,
        FS_PAYLOAD_SIGNED = 2,
        FS_PAYLOAD_ENCRYPTED = 4,
        FS_PAYLOAD_EXTERNAL = 8,
        FS_PAYLOAD_SIGNED_EXTERNAL = 10,
    } FSPayloadType;

    /** Configuration flags */
    enum FitSecEngineFlags {
        /** must be set to send requests for unknown AT certificates (default)*/
        FS_P2P_REQ_AT = 0x01,

        /** must be set to send requests for unknown AA certificates (default)*/
        FS_P2P_REQ_AA = 0x02,

        /** must be set to include AT in next CAM if requested (default) */
        FS_P2P_SEND_AT = 0x04,

        /** must be set to include AA in next CAM if requested (default) */
        FS_P2P_SEND_AA = 0x08,

        /** must be set to send only the currently active AA (default) */
        FS_P2P_SEND_OWN_AA = 0x10,

        /** must be set to include AA in next CAM signed with DIGEST only(default) */
        FS_P2P_SEND_AA_WITH_DIGEST = 0x20,

        /** do not send AA certificate if it was already sent by other stations after request (default)*/
        FS_P2P_CANCEL_AA_REQUEST = 0x40,

        /** allow incomming messages with local certificates (debug only)*/
        FS_ALLOW_CERT_DUPLICATIONS = 0x80,

        FS_DEFAULT_FLAGS = 0x6F
    };

    typedef enum  {
        FSEvent_ChangeId,      // Pseudonym is about to be changed.
        FSEvent_IdChanged,     // Pseudonym was changed.
                               // event parameter is a pointer to the new FSCertificate
        FSEvent_Signed,        // In async mode only. Called when message is signed
        FSEvent_Validated,     // In async mode only. Called when message is validated
        
        FSEvent_Encrypted,     // In async mode only. Called when message is encrypted
        FSEvent_Decrypted,     // In async mode only. Called when message is decrypted

        FSEvent_CertStatus,    // Called when the status of some certificate is changed (revoked, expired, trusted, etc.) 

        FSEvent_HttpGetRequest,
        FSEvent_HttpPostRequest,
        FSEvent_StoreData,
    } FSEventId;

    typedef union FSEventParam FSEventParam;
    typedef bool (FitSec_Event_Fn)(FitSec * e, void * user, FSEventId event, const FSEventParam * params);

    typedef struct FitSecAppProfile {
        FSItsAidSsp aid;            // ITS application ID and ssp length and value meaning mask in sspData field;
                                    // 0 - ssp bit is permission bitfield
                                    // 1 - ssp bit is a part of value (version, ID or whatever)

        FSPayloadType payloadType;  // Default payload type

        unsigned int fields;        // Flags

        int      certPeriod;	    // period in milliseconds when certificate shall be sent within application messages
                                    // set to -1 to do not send certificates at all,
                                    // set to  0 to send certificates in each message (default)
                                    // set to 1000 (100 msec) to send each second (default for CAM).

        int      certChangePeriod;  // The certificate change period in seconds
        //TODO: to be continued: change pseudonym strategy, etc.
    } FitSecAppProfile;

    typedef enum {
        FS_MSG_USE_GENERATION_TIME     = 1,        // Put generation time field in security message header
        FS_MSG_USE_GENERATION_LOCATION = 1 << 1,   // Put generation location field in security message header
        FS_MSG_P2P_CERTIFICATE_REQUEST = 1 << 2,   // Allow P2P certificate request field in security message header
        FS_MSG_P2P_CERTIFICATE = 1 << 3,           // Allow to send certificate in P2P distribution in security message header
        FS_MSG_P2P_CRL_REQUEST = 1<<4,             // Allow to request CRL in P2P distribution
        FS_MSG_P2P_CTL_REQUEST = 1<<5,             // Allow to request CTL in P2P distribution
        FS_MSG_P2P_ALL = 0x07<<3,                  // Allow to request everything in P2P distribution
        
    }FitSecAppProfileFlags;
#define FS_FIELDS_CAM_DEFAULT   0x3D               // Allow to request everything in CAM but do not send generation location
#define FS_FIELDS_DEFAULT  0x03                    // Send time and location by default. P2P is not allowed

    typedef struct FitSecConfig
    {
        unsigned int                version;          // default protocol version (3)
        unsigned int                flags;            // see FitSecEngineFlags
        const FitSecAppProfile    * appProfiles;      // application Profiles
        const char                * hashEngine;       // hash engine: "openssl", "atlk", NULL by default
        const char                * signEngine;       // signing engine: "openssl", "atlk", NULL by default
        const char                * verifyEngine;     // signature verification engine: "openssl", "atlk", NULL by default
        const char                * encryptEngine;    // encrypting engine: "openssl", "atlk", NULL by default
        const char                * decryptEngine;    // decrypting engine: "openssl", "atlk", NULL by default
        const char                * symmEncryptEngine;// symmetric encrypting engine: "openssl", "atlk", NULL by default
        const char                * symmDecryptEngine;// symmetric decrypting engine: "openssl", "atlk", NULL by default
        const char                * macEngine;        // MAC engine: "openssl", "atlk", NULL by default
        const char                * randomEngine;     // random engine: "openssl", "atlk", NULL by default
        
        FitSec_Event_Fn*            cbOnSigned;       // user callback function to be called when the outgoing message is signed
        FitSec_Event_Fn*            cbOnValidated;    // user callback function to be called when the incoming message is validated
        FitSec_Event_Fn*            cbOnEncrypted;    // user callback function to be called when the outgoing message is encrypted
        FitSec_Event_Fn*            cbOnDecrypted;    // user callback function to be called when the incoming message is decrypted
        FitSec_Event_Fn*            cbOnEvent;        // user callback function to be called when some event is occured (@see FSEventId)
        void                      * cbOnEventUser;    // user pointer to be passed to all callback functions
        unsigned int                maxReceivedPoolSize; // maximum size of received AT certificate pool
        unsigned int                maxReceivedLifeTime; // maximum life time of received certificate
        unsigned int                purgePeriod;         // period in seconds when certificate pools must be purged. Set to 0 to do not purge
        unsigned int                encKeyStorageDuration; // time to keep symmetric encryption keys after last usage. Set to 0 to skip PSK.
        unsigned int                ctlCheckPeriod;        // check for CTL every XX seconds (set to at least 24 hours)
        unsigned int                crlCheckPeriod;        // check for CRL every XX seconds (set to at least 24 hours)
        int                         storeTrustInformation; // call user callback funtion to store received trust information and AA certs
        uint8_t                     ctlSeriesId[8];        // [SCSM only] CTL series to be used.
        int                         ctlQuorum;             // [SCMS only] CTL quorum (2 by default)
    } FitSecConfig;
    #define FS_DEFAULT_PROTOCOL_VERSION 3
    #define FS_DEFAULT_RECEIVED_LIFETIME 2
    #define FS_DEFAULT_PURGE_PERIOD FS_DEFAULT_RECEIVED_LIFETIME
    #define FS_DEFAULT_CTL_CHECK_PERIOD (24 * 3600) // each 24h
    #define FS_DEFAULT_CRL_CHECK_PERIOD (24 * 3600) // each 24h


    /** Initialize the config structure with default values */
    FITSEC_EXPORT void  FitSecConfig_InitDefault(FitSecConfig * cfg);
    FITSEC_EXPORT const FitSecConfig* FitSec_GetConfig(const FitSec * e);

    /** Find the profile information for the given ITS AID*/
    FITSEC_EXPORT const FitSecAppProfile* FitSecConfig_FindProfile(const FitSecConfig* cfg, FSItsAid aid);

    /** Create and initialize engine */
    FITSEC_EXPORT FitSec * FitSec_New(const FitSecConfig * config, const char * const name);

    /** Cleanup all data, forget all foreign certificates, 
        clean all local certificates if clean_local flag is set */
    FITSEC_EXPORT void FitSec_Clean(FitSec * e);
    
    /** Cleanup engine and free all allocated memory */
    FITSEC_EXPORT void FitSec_Free(FitSec * e);
    
    /** Get the engine name. This name is used for loggong only. */
    FITSEC_EXPORT const char * FitSec_Name(const FitSec * e);
    
    /** Install certificate (root, AA, local AT pseudonymes, any other)
     *  Install any kind of certificates: AA, AT, EC, EA, Root, etc.
     *  Local AT certificates shall be followed by private keys.
     *  TODO: support for HSM key sorage
     *  @param e     The FitSec engine
     *  @param cert         The buffer with the certificate data
     *  @param cert_length  The buffer size
     *  @param vkey         The verification private key. 
     *                      Required for AT certificates. Must be NULL for other types.
     *                      
     *  @param vkey_length  The size of the key
     *  @param ekey         The encryption private key.fitsec.
     *                      Optional for AT certificates. Must be NULL for other types.
     *  @param ekey_length  The size of the key
     *  @param perror       The status of the procedure. See fitsec_error.h.
     *  @return             The certificate structure or NULL if certificate is not installed.
     */
    FITSEC_EXPORT const FSCertificate * FitSec_InstallCertificate(FitSec * e,
        const char * cert, size_t cert_length,
        const char * vkey, size_t vkey_length,
        const char * ekey, size_t ekey_length,
        int * perror
    );
    
    /** Install previously loaded certificate (root, AA, local AT pseudonymes, any other)
     *  Install any kind of certificates: AA, AT, EC, EA, Root, etc.
     *  @param e            The FitSec engine
     *  @param cert         The previously loaded certificate
     *  @param perror       The status of the procedure. See fitsec_error.h.
     *  @return             The certificate structure.
     */
    FITSEC_EXPORT const FSCertificate* FitSec_InstallFSCertificate(FitSec* e,
        FSCertificate* cert,
        int* perror);

    /** This function must be called once after instalaion of all certificates to
        relink all issuers and validate all installed certificates.
        (The funsion is deprecated and doesn't make anything. )
    FITSEC_EXPORT void FitSec_RelinkCertificates(FitSec * e);
    */

    /** Returns currently used certificate associated with the application
     * @param aid The aplication ID.
     * @return The current application certificate  
     */

    FITSEC_EXPORT const FSCertificate *  FitSec_CurrentCertificate(FitSec* e, FSItsAid aid);

    /*******************************************************************************************/
    /****    Trust lists API                                                                ****/
    /*******************************************************************************************/
    /**
     * @brief Apply CTL/CRL information from the given message
     * 
     * Message must be of @see FITSEC_AID_CRL or @see FITSEC_AID_CTL application id
     * 
     * The function will perform message validation internally. Do not need to call
     * @see FitSec_ValidateSignedMessage before this function
     * 
     * @param e The FitSec engine
     * @param m The parsed message.
     * @return true if function made some changes.
     * 
     * @note Do not forget to call @see FitSec_RevalidateCertificates when one of the
     * calls to this function returns true.
     * 
     * @note The generationTime field of the 'm' must be set to the current time for
     * dropping out storred requests.
     */
    FITSEC_EXPORT bool FitSec_ApplyTrustInformationMessage(FitSec* e, FSMessageInfo * m);
    
    /**
     * @brief Apply CTL/CRL information from the given buffer.
     * 
     * The function parse message from the given buffer, and call the @see FitSec_ApplyTrustInformationMessage
     * 
     * @param e The FitSec engine
     * @param curTime The current ITS time. Needs for dropping out stored requests. 
     * @param data The message buffer
     * @param len Buffer size
     * @return Error code or zero on success.
     * 
     * @note Do not forget to call @see FitSec_RevalidateCertificates when one of the
     * calls to this function returns true.
     */
    FITSEC_EXPORT int  FitSec_ApplyTrustInformation(FitSec* e, FSTime32 curTime, const char * data, size_t len);

    /** Revoke certificate with given ID.
        The certificate (if found) will be marked as revoked.
        @ref FitSec_RevalidateCertificates shall be called after the serie of revokations.
        @return true if certificate was found and successfully revoked
    */
    FITSEC_EXPORT bool FitSec_RevokeCertificateId(FitSec* e, FSHashedId8 digest);

    /** Revalidate all certificate chains after the revocation.
     * 
     * This function must be called after the set of revocations. It will revalidate all installed and 
     * received certificates.
     * */
    FITSEC_EXPORT void FitSec_RevalidateCertificates(FitSec* e);

    /** Call user callback to update expired trust information (CRL and/or CTL).
     * @param e The FitSec engine
     * @param curTime The current ITS time. Needs to decide when to run requests.
     *                Set to 0 to force CRL/CTL requests.
     * @param user The user pointer to be passed to the callback
     */
    FITSEC_EXPORT void FitSec_RequestTrustInfo(FitSec* e, FSTime32 curTime, void * user);

    /*******************************************************************************************/
    /****    Certificate API                                                                ****/
    /*******************************************************************************************/

    /** Return certificate digest
        @return the HashedId8 of the certificate
        @deprected Use the @ref FSCertificate_Digest instead
    */
    FITSEC_EXPORT CDEPRECATED FSHashedId8 FitSec_CertificateDigest(const FSCertificate *) ;

    /** Return the expiration ITS time of the certificate
        @return the expiration time (seconds since ITS epoche) of the certificate
        @deprected Use the @ref FSCertificate_ExpiryTime instead
    */
    FITSEC_EXPORT CDEPRECATED uint32_t FitSec_CertificateExpiry(const FSCertificate *);

    /** Return the issuer of the certificate (or itself if self-signed)
        @return the certificate issuer
        @deprected Use the @ref FSCertificate_Issuer instead
    */
    FITSEC_EXPORT CDEPRECATED const FSCertificate * FitSec_CertificateIssuer(const FSCertificate *);

    /** Return the subject name of the certificate (if any) or NULL if not specified
        @return the certificate name
        @deprected Use the @ref FSCertificate_Name instead
    */
    FITSEC_EXPORT CDEPRECATED const char * FitSec_CertificateName(const FSCertificate *);

    /** Sets the subject name of the certificate for debuging purposes
        @return the new certificate name
        @deprected Use the @ref FSCertificate_SetName instead
    */
    FITSEC_EXPORT CDEPRECATED const char * FitSec_SetCertificateName(const FSCertificate *, const char * name);

    /** Return the state of the certificate: FS_CERT_TRUSED, FS_CERT_INVALID or 0 if unknown
        @return the certificate state
        @deprected Use the @ref FSCertificate_GetState instead
    */
    FITSEC_EXPORT CDEPRECATED uint32_t FitSec_CertificateState(const FSCertificate* c);

    /** Return OER representation of the certificate (if was read from OER)
     * @return pointer to OER buffer or NULL if not (yet) read from buffer
        @deprected Use the @ref FSCertificate_Buffer instead
    */
    FITSEC_EXPORT CDEPRECATED const char * FitSec_CertificateBuffer(const FSCertificate * c, size_t * len);

    /** Find a local end entity certificate conformed to request conditions.
     *   @param e        pointer to the FitSec engine
     *   @param aidssp   the identifier of the application and SSP bitmask defining the actual message content.
     *   @param position the current geographic position. Can be NULL to skip this restriction.
     *   @param time     the current time. Can be 0 to skip this restriction.
     *   @param error    will be set to nonzero value if error occured.
     * 
     *   NOTE: This function will never trigger the ID changing process.
     */
    FITSEC_EXPORT FSCertificate *  FitSec_SelectEECertificate(FitSec * e, const FSItsAidSsp * appssp, const FSLocation * position, FSTime64 time, int* perror);

    /** Find an authority certificate, which is able to issue the end entity certificate, conformed to request conditions.
     *   @param e         pointer to the FitSec engine
     *   @param name_pattern The filename-like pattern to match the CA name. Use NULL to skip name check
     *   @param app       the application ID and SSP defining required CA application permission
     *                    For ETSI model request for EA shall contain at least 623:0x0104 and for AA - 623:0x0110 
     *   @param assp      the application ID and SSP defining EE application permissions.
     *                    For ETSI model request for EA shall contain at least 623:0x0110.
     *                    Request for AA shall contain AID:SSP for requested applications.
     *   @param rssp      the application id and SSP defining EE request permissions.
     *                    Must be set to NULL for ETSI model.
     *   @param region    the geographic region. Can be NULL to skip this restriction.
     *   @param startTime the time when certificate validity is started.
     *   @param endTime   the time when certificate validity is ended.
     *   @param error     will be set to nonzero value if error occured.
     */
    FITSEC_EXPORT FSCertificate *  FitSec_SelectCACertificate(  FitSec * e, 
                                                                const char * name_pattern,
                                                                const FSItsAidSsp * app,  
                                                                const FSItsAidSsp * assp, const FSItsAidSsp * issp,
                                                                const FSGeoRegion * region,
                                                                FSTime64 startTime, FSTime64 endTime,
                                                                int* perror);

    /** Select certificate to be used as current pseudonym.
     *  Function doesn't validate the certificate. 
     *   @param e       pointer to the FitSec engine
     *   @param aid     The identifier of the application where the pseudonym shall be changed.
     *                  Use FITSEC_AID_ANY to change ID for all application.
     *   @param cert_id The digest of the certificate to be selected.
     * 
     *   NOTE: This function may trigger the Id changing process.
     */
    FITSEC_EXPORT FSCertificate * FitSec_Select(FitSec * e, FSItsAid aid, FSHashedId8 cert_id);

    /** Request for Pseudonym change.
     *  The request for the seudonym change will be registered.
     *  The actual ID change will be made with the next outgoing signed message if the ID change is not locked or
     *    will be postponed until unlock.
     *  The OnEvent callback will be called twice with following events:
     *     * FSEventChangeId  - Before the change procedure, during this function execution;
     *     * FSEventIdChanged - After the procedure. This event will be issued later when ID change is actually made
     *   @param e        Pointer to the FitSec engine
     *   @param aid      The focused application. Use FITSEC_AID_ANY to change ID for all application. 
     */
    FITSEC_EXPORT bool FitSec_ChangeId(FitSec* e, FSItsAid aid);

    /** Lock/unlock pseudonym change procedure
     *   
     *   @param e       pointer to the FitSec engine
     *   @param aid     the application id to be locked.
     *                  Use FITSEC_AID_ANY to lock all application.
     *   @param lock    lock or unlock flag
     *
     *   NOTE: This function may trigger the Id changing process.
     */
    FITSEC_EXPORT bool FitSec_LockIdChange(FitSec* e, FSItsAid aid, bool lock);

    /** Returns the message corresponding to the error value */
    FITSEC_EXPORT const char * FitSec_ErrorMessage(int err);
    FITSEC_EXPORT const char * FitSec_ErrorMessageBuf(int err, char* const buf, size_t bsize);

    typedef enum {
        FS_SI_UNKNOWN = 0,
        FS_SI_AUTO = 0,
        FS_SI_DIGEST,
        FS_SI_CERTIFICATE,
        FS_SI_SELF,
    } FSSignerInfoType;
    
    struct FSMessageInfo {
        int                   status;             ///< Status or error value.
        const char *          errmsg;             ///< Error description.

        char *                message;            ///< Pointer to the message buffer.
                                                  ///    It is up to the application to manage this memory buffer
        size_t                messageSize;        ///< Message buffer size

        char *                payload;            ///< Pointer to the message payload
                                                  ///    Usually it points inside the message buffer, 
                                                  ///    but in the case of en/decryption this can be pointed to internally allocated buffer.
                                                  ///    Anyway, application shall never change or delete this memory.
        size_t                payloadSize;        ///< Message payload size

        FSPayloadType         payloadType;        ///< Type of the payload
        FS3DLocation          position;           ///< Message position. See functions descriptions.
        FSTime64              generationTime;     ///< Message generation time. See functions descriptions.
        union{
            struct {
                union{
                    FSCertificate   * cert;       ///< Certificate to be used for signature
                    FSPublicKey     * pub;        ///< Needs to be set for SELF-verification
                    FSPrivateKey    * priv;       ///< Needs to be set for SELF-signing
                };
                FSSignerInfoType      signerType; ///< Signer type (certificate/digest/noSignature)
                FSItsAidSsp           ssp;        ///< SSP of the message to be used to select proper certificate 
                FSCurve               alg;        ///< PK algorithm to be used for SELF-signing
            }sign;                                ///  or to inform the application about allowed message content
            struct {
                union {
                    FSCertificate   * cert;       ///< Certificate to be used for encryption / decription
                    FSPublicKey     * pub;        ///< Needs to be set for EC PSK-encryption
                    FSPrivateKey    * priv;       ///< Needs to be set for EC PSK-decription
                };
                struct {
                    FSSymmAlg         alg;            ///< Symmetric encryption key algorithm
                    uint8_t         * key;            ///< Symmetric encryption key (external memory)
                    FSHashedId8       pskId;          ///< Symmetric encryption key id
                }symm;
            }encryption;
        };

        /// @internal
        uint32_t              _flags;
        void *_ptrs[10];
        /// @endinternal
    };

    typedef enum {
     FSDT_UNKNOWN,
     FSDT_CERTIFICATE,
     FSDT_CTL,
     FSDT_CRL,   
     FSDT_LINK   
    }FSDataType;

    union FSEventParam
    {
        struct {
            FSItsAid             aid;
            const FSCertificate* old_cert;
            const FSCertificate* new_cert;
        }idChange;
        FSMessageInfo msg;

        struct {
        	FSCertificate * certificate;
        	FSCertificateState from;
        	FSCertificateState to;
        }certStateChange;

        struct {
            const char url[1];
        }httpGet;

        struct {
            const char * url;
            const char * body;
            size_t       bodylen;
        }httpPost;

        struct {
            FSHashedId8 id;
            FSDataType  type;
            size_t      len;
            const char *data;
        }store;
    };

    FITSEC_EXPORT bool FitSec_CallEventCallback(FitSec * e, void * user, FSEventId event, const FSEventParam * params);

    /** Allocate the FSMessageInfo structure and the message buffer  of given size */
    FITSEC_EXPORT FSMessageInfo* FSMessageInfo_Allocate(size_t maxBufSize);
    
    /** Allocate the FSMessageInfo structure and associate it with the given buffer.
     *   The FSMessageInfo structure DOESN'T own the memory buffer.
     */
    FITSEC_EXPORT FSMessageInfo* FSMessageInfo_AllocateWithBuffer(void * const buf, size_t bufSize);
    
    /** Allocate buffer for the message info structure
     *  Do not forget to free the buffer calling this function with 0 size
     *  FSMessageInfo_Free will delete buffer automatically
     */
    FITSEC_EXPORT FSMessageInfo * FSMessageInfo_AllocateBuffer(FSMessageInfo * m, size_t allocSize);

    /** Free the FSMessageInfo structure and (optionally) the message buffer.
     */
    FITSEC_EXPORT void FSMessageInfo_Free(FSMessageInfo*);

    /** Copy content of 1 message info structure into another.
     *  Buffer data is also copied.
     *  to->messageSize shall be more or equal to the from->messageSize.
     */
    FITSEC_EXPORT size_t FSMessageInfo_CopyWithBuffer(FSMessageInfo * to, const FSMessageInfo * from);

    /** Swap buffers of 2 FSMessageInfo structures.
     * The buffer ownership is also swapped
     */
    FITSEC_EXPORT void FSMessageInfo_SwapBuffers(FSMessageInfo * m1, FSMessageInfo * m2);

    /** Associate the FSMessageInfo structure with the given buffer.
     *   The FSMessageInfo structure DOESN'T own the memory buffer.
     */
    FITSEC_EXPORT void FSMessageInfo_SetBuffer(FSMessageInfo * m, void * const buf, size_t bufSize);

    /** Cleanup MessageInfo structure pool. Free all allocated memory.
        This function must be called after deinitialization of all fitsec engines in order to deallocate all memory buffers
    */
    FITSEC_EXPORT void FSMessageInfo_Cleanup(void);

    /** Proceed with enqueued asynchronous tasks.
        This function must be called from the working thread to execute enqueued operations.
     */
    FITSEC_EXPORT bool FitSec_ProceedAsync(FitSec * const e);

    /** Prepare the security envelop headers according to the payload type.
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @return        message size or 0 for error
     *
     *  Meaning of fields in FSMessageInfo depends of the value of the payloadType field
     *  ---------------|------------------------------------------------------------------------------------
     *  message        | in:  the pointer to the output buffer.
     *  messageSize    | in:  the maximum size of the output buffer.
     *  payloadType    | in:  determines the type of the envelop to be prepared.
     *  payload        | out: the pointer to the output buffer where payload shall be stored by the application
     *  payloadSize    | out: the maximum amount of space for the payload
     */
    FITSEC_EXPORT size_t FitSec_PrepareMessage(FitSec * e, FSMessageInfo* m);

    /** Finalize message preparation and do necessary crypto operations: sygn, encrypt, etc.
     *  @param e          [In]      The engine
     *  @param m          [In/Out]  Message Info structure
     *  @param userObject [In]      Object to be passed to async callbacks.
     *  @return           message size or 0 for error
     *
     *  Meaning of fields in FSMessageInfo depends of the value of the payloadType field. See correspondent function description
     *  ---------------|------------------------------------------------------------------------------------
     *  message        | in:  the pointer to the output buffer.
     *  messageSize    | in:  the maximum size of the output buffer.
     *  payloadType    | in:  determines the type of the envelop to be prepared.
     *  signerType     | in/out: signer info of the message. Set to FS_SI_AUTO for default behavior.
     *  generationTime | in:  current ITS time
     *  position       | in:  last known geo position (optional)
     *  payload        | out: the pointer to the output buffer where payload shall be stored.
     *  payloadSize    | out: the maximum size of the payload.
     *  message        | out: the pointer to the output buffer (equal to the buf parameter).
     *  messageSize    | out: the maximum size of the output buffer (equal to the bufsize parameter).
     */
    FITSEC_EXPORT size_t FitSec_FinalizeMessage(FitSec * e, FSMessageInfo* m);
    FITSEC_EXPORT size_t FitSec_FinalizeMessageAsync(FitSec * e, FSMessageInfo* m, void * const userObject);

    /** Unsecured envelop for the message.
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @param buf     [Out]     Pointer to the buffer to store the message envelop
     *  @param bufsize [In]      The max size of the buffer
     *  @return        the size of the header already stored in the buffer or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *                 | FitSec_UnsecuredMessage
     *  ---------------|------------------------------------------------------------------------------------
     *  payload        | out: the pointer to the output buffer where payload shall be stored.
     *  payloadSize    | out: the maximum size of the payload.
     *  message        | out: the pointer to the output buffer (equal to the buf parameter).
     *  messageSize    | out: the maximum size of the output buffer (equal to the bufsize parameter).
     */
    FITSEC_EXPORT size_t FitSec_PrepareUnsecuredMessage(FitSec * e, FSMessageInfo* m);

    /** Finalize unsecured message envelop.
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @return        message size or 0 for error
     *
     *  Meaning of fields in FSMessageInfo depends of the value of the payloadType field. See correspondent function description
     *  ---------------|------------------------------------------------------------------------------------
     *  payloadType    | in:  determines the type of the envelop to be prepared.
     *  payload        | in:  the pointer to the output buffer where payload is stored.
     *  payloadSize    | in:  the size of the payload.
     *  message        | in/out: the pointer to the output buffer.
     *  messageSize    | in/out: the maximum size of the output buffer.
     */
    FITSEC_EXPORT size_t FitSec_FinalizeUnsecuredMessage(FitSec * e, FSMessageInfo* m);
    
    /** Prepare Encrypted ITS message envelop
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @param buf     [Out]     Pointer to the buffer to store the message
     *  @param bufsize [In]      The max size of the buffer
     *  @return        message size or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------------------------
     *  payloadType    | in: the type of the payload: must be FS_PAYLOAD_ENCRYPTED
     *  cert           | in: the destination certificate.
     *  payload        | out: the pointer to the output buffer where payload shall be stored.
     *  payloadSize    | out: the maximum size of the payload.
     */
    FITSEC_EXPORT size_t FitSec_PrepareEncryptedMessage(FitSec * e, FSMessageInfo* m);

    /** Add certificate as an encrypted message receipient.
     *  @param e           [In]      The engine
     *  @param m           [In/Out]  Message Info structure
     *  @param receipient  [In]      The certificate digest.
     *  @return            message size or 0 for error
     *
       Target certificate shall have encryption public key.
       Up to 8 certificate encryption targets can be set for the message.
     */
    FITSEC_EXPORT size_t FitSec_AddEncryptedMessageCertificateReceipient(FitSec * e, FSMessageInfo* m, FSHashedId8 receipient);
    
    /** Install pre-shared key in the DB
     *  @param e           [In]      The engine
     *  @param alg         [In]      The encryption algorythm
     *  @param curTime     [In]      The current ITS time. (msg generation time / 1000000,  for example)
     *  @param symmKey     [In]      The encryption key. Length depends of algorithm.
     *  @param digest      [In]      The encryption key digest if the key is already stored in the DB 
     *  @return            The digest of the key
     */
    FITSEC_EXPORT FSHashedId8 FitSec_InstallPreSharedSymmKey(FitSec * e, FSSymmAlg alg, uint32_t curTime, const uint8_t * symmKey, FSHashedId8 digest);

    /** Add pre-shared key as ancrypted message receipient.
     *  @param e           [In]      The engine
     *  @param m           [In/Out]  Message Info structure
     *  @param alg         [In]      The encryption algorythm
     *  @param symmKey     [In]      The encryption key. Length depends of algorithm.
     *  @param digest      [In]      The encryption key digest if the key is already stored in the DB 
     *  @return            message size or 0 for error
     *
       symKey == NULL && digest == 0     - Generate new key. Return it in the message body
       symKey == NULL && digest != 0     - Search for the key in the DB. Error if not found
       symKey != NULL && digest ignored  - Use symKey. Check it in the DB
     */
    FITSEC_EXPORT size_t FitSec_AddEncryptedMessagePSKReceipient(FitSec * e, FSMessageInfo* m,
                                                                 FSSymmAlg alg, const uint8_t * symmKey, FSHashedId8 digest);

    /** Finalize encrypted ITS message envelop
     *  @param e           [In]      The engine
     *  @param m           [In/Out]  Message Info structure
     *  @return            message size or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------------------------
     *  message        | in/out: the pointer to the output buffer.
     *  messageSize    | in: the maximum size of the output buffer.
     *                 | out: the actual size of the message.
     *  payloadType    | in: the type of the payload: must be FS_PAYLOAD_ENCRYPTED
     *  payload        | in: the pointer to the output buffer where payload is stored, as returned from FitSec_PrepareEncryptedMessage
     *  payloadSize    | in: the actual size of the payload.
     */
    FITSEC_EXPORT size_t FitSec_FinalizeEncryptedMessage(FitSec * e, FSMessageInfo* m);
//    FITSEC_EXPORT bool   FitSec_FinalizeEncryptedMessageAsync(FitSec * e, FSMessageInfo* m, void * const userObject);

    /** Create signed ITS message envelop
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @return        message size or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------------------------
     *  message        | in/out: the pointer to the output buffer.
     *  messageSize    | in:     the maximum size of the output buffer.
     *                 | out:    the actual size of the message.
     *  payloadType    | in:     the type of the payload: must be FS_PAYLOAD_SIGNED  or FS_PAYLOAD_SIGNED_EXTERNAL
     *  payload        | in/out: the pointer to the payload data.
     *  payloadSize    | in/out: the payload size.
     *  position       | in:     current position. Not needed for CAM
     *  generationTime | in:     the timestamp of the last GPS fix
     *  signerType     | in/out: signer info of the message. Set to FS_SI_AUTO for default behavior.
     *  cert           | in/out: certificate to be used to sign message. Set to NULL for default behavior.
     *  ssp            | in:     the AID and SSP bits representing content of the message.
     *                 |            These bits will be used to select the proper certificate.
     */
    FITSEC_EXPORT size_t FitSec_SignedMessage(FitSec * e, FSMessageInfo* m);

    /** Prepare the buffer for the signed ITS message envelop
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @return        message size or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------------------------
     *  message        | in:     the pointer to the output buffer.
     *  messageSize    | in:     the maximum size of the output buffer.
     *  payloadType    | in:     the type of the payload. The FS_PAYLOAD_SIGNED or FS_PAYLOAD_SIGNED_EXTERNAL are expected
     *  position       | in:     current position. Not needed for CAM
     *  generationTime | in:     the timestamp of the last GPS fix
     *  signerType     | in/out: signer info of the message. Set to FS_SI_AUTO for default behavior.
     *  cert           | in/out: certificate to be used to sign message. Set to NULL for default behavior.
     *  ssp            | in:     the AID and SSP bits representing content of the message.
     *                 |             These bits will be used to select the proper certificate.
     *  payload        | out: the pointer to the output buffer where payload shall be stored.
     *  payloadSize    | out: the maximum size of the payload.
     */
    FITSEC_EXPORT size_t FitSec_PrepareSignedMessage(FitSec * e, FSMessageInfo* m);

    /** Finalize signed ITS message envelop. Perform necessary crypto operations
     *  @param e       [In]      The engine
     *  @param m       [In/Out]  Message Info structure
     *  @return        message size or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------------------------
     *  message        | in:  the pointer to the output buffer.
     *  messageSize    | in:  the maximum size of the output buffer.
     *                 | out: the actual size of the message.
     *  payloadType    | in:  the type of the payload: must be FS_PAYLOAD_SIGNED  or FS_PAYLOAD_SIGNED_EXTERNAL
     *  position       | in:  current position. Not needed for CAM
     *  generationTime | in:  the timestamp of the last GPS fix
     *  signerType     | in/out: signer info of the message. Set to FS_SI_AUTO for default behavior.
     *                 | out: the actual signer type of the message.
     *  cert           | in:  certificate to be used to sign the message. Set to NULL for default behavior.
     *                 | out: certificate used to sign the message.
     *  ssp            | in: the AID and SSP bits representing content of the message.
     *                 |     These bits will be used to select the proper certificate.
     *  payload        | in: the pointer to the output buffer where payload shall be stored.
     *  payloadSize    | in: the maximum size of the payload.
     */
    FITSEC_EXPORT size_t FitSec_FinalizeSignedMessage(FitSec * e, FSMessageInfo* m);
    FITSEC_EXPORT size_t FitSec_FinalizeSignedMessageAsync(FitSec * e, FSMessageInfo* m, void * const userObject);

    /** Parse ITS message.
     *  Parse the message and remove one existing envelop. It can be one of:
     *    - Signed data
     *    - Encrypted data
     *    - Unsecured data
     *    Fill in the FSMessageInfo structure by the message data.
     *  @param e       [In]      The engine
     *  @param info    [In/Out]  Message information.
     *  @return        size of consummed data or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------
     *  message        | in: the pointer to the message buffer.
     *  messageSize    | in: the size of the message buffer.
     *  generationTime | in: the current ITS time
     *  payload        | out: points to the payload buffer.
     *                 |      It can point to the encoded inner data structure in case of Signed or Encrypted data envelop
     *  payloadSize    | out: the size of message payload
     *  payloadType    | out: the type of the payload (Signed, Encrypted, Unsecured,...)
     *  ---------------|--------------------------------------------
     *      SIGNED payload type:
     *  position       | out: the remote position where message has been signed (if any)
     *  generationTime | out: the time when message has been generated
     *  signerType     | out: signer info of the message.
     *  cert           | out: the AT certificate that has been used to sign message
     *  ssp            | out: the AID of the message and the SSP of the signing certificate
     */
    FITSEC_EXPORT size_t FitSec_ParseMessage(FitSec* e, FSMessageInfo* info);
    FITSEC_EXPORT size_t FitSec_ParseSignedMessage(FitSec* e, FSMessageInfo* m);
    FITSEC_EXPORT size_t FitSec_ParseUnsecuredMessage(FitSec* e, FSMessageInfo* m);
    FITSEC_EXPORT size_t FitSec_ParseEncryptedMessage(FitSec* e, FSMessageInfo* m);

    /** Validate signed ITS message.
     *  @param e       [In]      The engine
     *  @param info    [In/Out]  Message information received from FitSec_ParseSignedMessage
     *  @return        the actual size of the message or 0 in case of error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------
     *  message        | in: the pointer to the message.
     *  messageSize    | in: the size of the message.
     *  position       | in: the remote position where message has been signed
     *  generationTime | in: the time when message has been generated
     *  cert           | in: the AT certificate that has been used to sign message
     *  ssp            | in: the AID of the message and SSP of the certificate
     *  tbs            | in: the pointer to the ToBeSigned part of the message
     *  tbsSize        | in: the size of the ToBeSigned part of the message
     */

    FITSEC_EXPORT bool FitSec_ValidateSignedMessage(FitSec * e, FSMessageInfo * info);
    FITSEC_EXPORT bool FitSec_ValidateSignedMessageAsync(FitSec * e, FSMessageInfo * info, void * const userObject);

    /** Decrypt ITS message.
     *  @param e       [In]      The engine
     *  @param info    [In/Out]  Message information.
     *  @return        message size or 0 for error
     *
     *  Description of fields in FSMessageInfo:
     *  ---------------|--------------------------------------------
     *  generationTime | in: the current ITS time
     *  payload        | out: points to the decrypted payload (output buffer)
     *  payloadSize    | out: the size of message payload
     *  payloadType    | out: the type of the message payload
     */
    FITSEC_EXPORT size_t FitSec_DecryptMessage(FitSec* e, FSMessageInfo* info);
    FITSEC_EXPORT size_t FitSec_DecryptMessageAsync(FitSec* e, FSMessageInfo* info, void * const userObject);


#ifdef __cplusplus
}
#endif
#endif
