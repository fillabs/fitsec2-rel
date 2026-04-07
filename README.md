# FITSec - The ITS Security implementation

## Overview ##

The FitSec library provides a high-performance security engine for processing messages and certificates within Intelligent Transport Systems (ITS) communications.

### Supported Specifications ###
The library implements the following standards:
- [IEEE 1609.2-2022](https://standards.ieee.org/ieee/1609.2/10258/) - Main specification for ITS security message headers and certificate formats.
- [ETSI TS 103 097 v2.1.1](https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/02.01.01_60/ts_103097v020101p.pdf) - The ETSI profile for IEEE 1609.2.
- [ETSI TS 102 941 v2.2.1](https://www.etsi.org/deliver/etsi_ts/102900_102999/102941/02.02.01_60/ts_102941v020201p.pdf) - PKI and trust mechanisms.
- [ETSI TS 103 601 v2.2.1](https://www.etsi.org/deliver/etsi_ts/103600_103699/103601/01.01.01_60/ts_103601v010101p.pdf) - ETSI ITS security extensions.
- [ETSI TS 103 759 v2.1.1](https://www.etsi.org/deliver/etsi_ts/103700_103799/103759/02.01.01_60/ts_103759v020101p.pdf) - Misbehaviour reporting protocol (ongoing).

Basic Features:
- __Efficiency__: Optimized for minimal memory and CPU consumption.
- __Extensibility__: Plugin interface for software cryptographic libraries and Hardware Security Modules (HSMs).
- __Flexibility__: Supports both synchronous and asynchronous message processing.
  
Secured Message Handling:
- Encoding and decoding of ITS secured messages (including extensions) per ETSI TS 103 097 v2.1.1.
- Signature generation and verification.
- Message validation based on signing certificate restrictions.
- Peer-to-peer certificate distribution.
   
PKI features:
- Support for multiple Root, Enrolment (EA), and Authorization (AA) Certificate Authorities.
- Independent Enrolment Credential (EC) and Authorization Ticket (AT) certificate pools for each ITS-S application.
- Creation and handling of certificate requests (EC or AT).
- Automatic AT certificate selection for outgoing messages.
- Support for Certificate Revocation Lists (CRL) and Trust Lists (CTL/ECTL).
- Explicit and implicit certificate support.
- Peer-to-peer CRL/CTL requests.
- Certificate requests repetition.

### Compatibility & Environment ###
The library is compatible with any communication protocol, including GeoNetworking ([ETSI EN 302 636-4-1](http://www.etsi.org/deliver/etsi_en/302600_302699/3026360401/01.02.01_60/en_3026360401v010201p.pdf)). It is written in standard C for cross-platform compatibility and has been tested on:
- Linux: gcc (x86, ARM)
- Windows: MinGW32, Cygwin, Visual C++ 14 (x86)

__Note__: Binaries provided for testing may contain feature restrictions. Please contact the author for full versions.
__Simulator__: Try the library using the ITS message simulator: [fsmsggen](https://github.com/fillabs/fsmsggen)

### Dependencies ###
Dependencies are managed via git submodules:<br/>
- [cshared](https://www.github.com/fillabs/cshared/) - An open-source utility library.
- [fscrypt](https://www.github.com/fillabs/fscrypt/) - A wrapper library for cryptographic engines. Currently supported:
  - [OpenSSL](https://www.openssl.org/).
  - AutoTalk Craton2 HSM engine (experimental).
  - Custom engines can be implemented via the plugin API. See fscrypt README.

## User API ##
The primary API is defined in [_fitsec.h_](fitsec.h) header file.

### Initialization ###
Initialize the engine instance using FitSec_New, which requires a FitSecConfig structure.

__Step 1__. First of all, Initialize the engine instance using using the __`FitSec_New`__ call.<br/>
This function takes a configuration structure of type _FitSecConfig_ as a parameter.

The _FitSecConfig_ contains the following configuration fields:<br/>
- __`version`__ - A protocol version. Set it to `3` according to IEEE 1609.2 and ETSI TS 103 097
- __`flags`__ - Configuration flags bitmap. See the __`FitSecEngineFlags`__ data type for possible bit fields.
- __`appProfiles`__ - An array of __`FitSecAppProfile`__ structures describing ITS applications:
  - __`aid`__ - ITS application ID
  - __`payloadType`__ - Message payload type for outgoing messages.
  - __`fields`__ - Bitmap of mandatory outgoing message elements. See _`FitSecAppProfileFlags`_ for details.
  - __`certPeriod`__ - Delay (ms) between certificate inclusions. Special values are:
    - `-1` - never send certificates, use digests in all messages
    - `0` - send certificates within each outgoing message (default for DENM, SPAT, MAP, etc.)
    - some positive value defines a maximum delay between two messages containing certificates. For example set to 1000 to send certificate each second (default for RSU CAM)
  - __`certChangePeriod`__ - Maximum lifetime (s) for an AT certificate before rotating to a new one from the pool.
- __`encKeyStorageDuration`__ Duration in seconds to keep previously used symmetric key for decrypting incomming messages (only for PKI messages for now).
-__`storeTrustInformation`__ Call user call-back to store received CA certificates, CRLs and CTLs.

Crypto engines:<br/>
The library provides a flexible way for using different crypto engines for different purposes. Crypto engines are referenced by name.
Two crypto engines are supported now: `openssl` and `atlk` (AutoTalk Craton 2 HSM library).
Please have a look on cryptographic plugin definition in _fitsec_crypt_plugin.h_ and _fitsec_hash_plugin.h_.
- __`hashEngine`__ crypto engine for hash functions. Currently "openssl" and "atlk" are supported, set to NULL for autoselect
- __`signEngine`__ crypto engine for signing: "openssl", "atlk", NULL by default
- __`verifyEngine`__ crypto engine for sugnature verification: "openssl", "atlk", NULL by default
- __`encryptEngine`__ crypto engine for EC encrypting engine: "openssl", "atlk", NULL by default
- __`decryptEngine`__ crypto engine for EC decryption: "openssl", "atlk", NULL by default
- __`symmEncryptEngine`__ crypto engine for symmetric encryption: "openssl", "atlk", NULL by default
- __`symmDecryptEngine`__ crypto engine for symmetric decryption: "openssl", "atlk", NULL by default
- __`macEngine`__ crypto engine for MAC calculatoin: "openssl", "atlk", NULL by default
- __`randomEngine`__ crypto engine for random function: "openssl", "atlk", NULL by default

Callbacks:<br/>
The library has two work modes: synchronous and asynchronous. In asynchronous mode the library interacts with the upper layer using the set of callback functions. The following callbacks are defined in the configuration structure:
- __`cbOnSigned`__ user callback function to be called when the outgoing message is signed and ready to be sent to the network
- __`cbOnValidated`__ user callback function to be called when the incoming message is validated
- __`cbOnEncrypted`__ user callback function to be called when the outgoing message is encrypted
- __`cbOnDecrypted`__ user callback function to be called when the incoming message is decrypted
- __`cbOnEvent`__ user callback function to be called when some event is occurred (@see FSEventId)
- __`cbOnEventUser`__ user pointer to be passed to all callback functions

Certificate pool parameters:<br/>
- __`maxReceivedPoolSize`__ Maximum number of received AT certificates stored.
- __`maxReceivedLifeTime`__ Maximum life time of received AT certificates.
- __`purgePeriod`__ period in seconds when received certificate pools must be purged. Set to 0 to never purge the pool. In this case two previous parameters doesn't make any sense.
- __`ctlCheckPeriod`__ Interval in seconds between new CTL checks. Typically shall be at least 24h.
- __`crlCheckPeriod`__ Interval in seconds between new CRL checks. Typically shall be at least 24h.

This configuration structure can be initialized using the __`FitSecConfig_InitDefault`__ and modified according to user's needs. Please have a look at the [_fitsec.h_](fitsec.h) for the description of configuration fields.

__Step 2__. Install all necessary certificates using function __`FitSec_InstallCertificate`__.<br/>
Any types of certificates can be installed: Root, TLM, EA, EC, AA, AT or any other custom certificate types in any order.
Authorization tickets shall be followed by the correspondent private keys or HSM key identifiers.
> _Important_: all self-signed (Root) certificates installed by this function will be verified against itself and __considered as trusted by default__.

CTL/ECTL/CRL can also be installed. See [CTL/CRL support](#ctl-crl_support) chapter for information. 

__Step 3__. Now the engine is ready to work. Messages processing can start.

### Outgoing Signed Messages ###
Processing occurs in two stages to optimize memory by operating directly within the buffer provided by the facility layer:<br/>
- preparation of the message header
- signing the message

To optimize the memory manipulation efforts, all message operations performed directly within the message buffer, provided by the facility layer.
This buffer with encoded message, can be passed later to the transport layer. The buffer shall contain enough space for all security headers, certificate(s) and the message payload.

#### Workflow with GeoNetworking messages ####
According to the GeoNetworking specification, Security Header takes place between Basic GN Header and Common GN Header elements in GeoNetworking message structure.

Geonetworking layer shall execute the following steps to encode a secured message:
- allocate (or prepare) a memory buffer.
- prepare Basic GN Header strucutre.
- call __`FitSec_PrepareSignedMessage`__ to generate Security header
- populate the payload starting by Common GN Header, following by BTP and facility data.
- update the `payloadSize` field in message information structure.
  >(Note: Please don't spend too much time in this stage to avoid CAM signing rules violation.)
- call __`FitSec_FinalizeMessage`__ or __`FitSec_FinalizeSignedMessageAsync`__ to sign the message.

Please see the [_fitsec.h_](fitsec.h) for function descriptions.

#### Preparing the message header ####
Call __`FitSec_PrepareSignedMessage`__ to create the Security Header element and store it in the outgoing buffer.

This function must be called with the message information structure, containing following information:
- `message` and `messageSize` containing the outgoing buffer address and size
- `payloadType` containing the type of the security envelop: signed, encrypted, etc. _(optional, set to `FS_PAYLOAD_AUTO` by default)_. 
- `position` containing current geographic position if necessary. _(optional, not needed for CAM)_
- `generationTime` containing the timestamp when the last GPS fix has been reached.
- `sign` containing information about signing procedure. Following fields shall be set:
  - `signerType` Set to `FS_SI_AUTO` to set the signer type automatically, according to the ITS application ID. Other values are:
    - `FS_SI_CERTIFICATE` or `FS_SI_DIGEST` - use certificate or certificate digest to sign the message.<br/>
       Certificate can be provided in `sign.cert` field or can be selected automatically according to provided time, position and ITS application ID.
    - `FS_SI_SELF` - sign message using the private key provided in `sign.priv` field.<br/>
       This field can be NULL during the preparation stage but should be set to a real value on the final stage.
       The signing algorithm shell be specified in `sign.alg` field.
  - `ssp` containing application ID and SSP bits, describing the content of the message.<br/>
     The ITS AID list can be found on [ISO TS17419 V2016-02-09: "ITS-AID_AssignedNumbers"](http://standards.iso.org/iso/ts/17419/TS17419%20Assigned%20Numbers/TS17419_ITS-AID_AssignedNumbers.pdf). SSP bits values described in ITS service standards.

The function creates the ITS Security Header in the provided buffer and fill the message information structure with:
- `payload` containing the pointer inside the memory buffer where the payload data shall be copied.
- `payloadSize` containing the maximum size of the payload buffer.
- `sign` containing some information about signing procedure:
  - `signerType` is set to the actual type of signer: `FS_SI_CERTIFICATE`, `FS_SI_DIGEST` or `FS_SI_SELF`
  - `cert` is set to the certificate to be used to sign message if `signerType` is set to the `FS_SI_CERTIFICATE` or `FS_SI_DIGEST`. This value can be changed before or during the final stage. Set to NULL for automatic selection.

The data in the message information structure will be used on the next stage, so please keep it unchanged, excepting the payload size field.

The function returns the amount of bytes occupied in the output buffer by Secured Header or `0` if error occured. The error ID is provided in the message information structure.

Please see the [_fitsec.h_](fitsec.h) for function descriptions.

#### Preparing of payload ####

The GeoNetworking layer than needs to create the Common Header and, optionally the Extended Header elements, and add the facility layer payload into the outgoing buffer.

The total length of all these elements shall be provided to the library using `payloadSize` field in the message information structure.

#### Signing of the message ####
When the payload buffer is ready, the message shall be actually signed or encrypted, depending of it's payload type.
The user code must call __`FitSec_FinalizeMessage`__ to perform these tasks. For asynchronous procedure the __`FitSec_FinalizeSignedMessageAsync`__ can be used.
This function takes same parameters as the __`FitSec_PrepareMessage`__.

The function returns the full size of secured packet or 0 if error occured. The error ID is provided in the message information structure.

### Outgoing Encrypted Messages ###
The library supports encryption based on IEEE 1609.2 specifications using algorithms defined in ETSI TS 103 097.
The procedure of message encryption is similar to signing:
- preparation of the buffer using __`FitSec_PrepareEncryptedMessage`__
- adding one or more recipients.
- applying the payload
- actual encrypting using __`FitSec_FinalizeEncryptedMessage`__ 

#### Preparing of the encryption headers ####
__`FitSec_PrepareEncryptedMessage`__ function shall be called to initialize the outgoing buffer with the message header.
The function should be called with the message information structure, containing at least:
- `message` and `messageSize` with the outgoing buffer address and size
- `payloadType` containing the type of the security envelop: signed, encrypted, etc. (optional, set to `FS_PAYLOAD_AUTO` by default).
- `generationTime` containing the timestamp, when the last GPS fix has been reached. This field is needed to select proper certificates and to process cached values.

#### Preparing of the encryption headers ####
The encrypted message can be addressed for up to 8 recipients. For the moment the library supports two types of encryption recipients: `certificate` or `pre-shared keys (PSK)`. Not more than 1 PSK recipient is allowed.

__`FitSec_AddEncryptedMessageCertificateRecipient`__ function add certificate into recipients list. This function shall be called with message information structure and the certificate id.

__`FitSec_AddEncryptedMessagePSKRecipient`__ add a PSK recipient into recipients list. The actual symmetric key can be provided in the `symkey` parameter or it can be referenced using `digest` if the key was used recently and is expected in the keys cache. The `encKeyStorageDuration` configuration parameter defines an encryption cache lifetime interval.

#### Preparing of payload ####
Similar to the signing procedure, the payload data shall be copied into the `payload` buffer.
The total length of the payload shall be set in the `payloadSize` field in the message information structure.

#### Finalize encryption ####
The actual encryption procedure is the final stage of the whole procedure. The function __`FitSec_FinalizeEncryptedMessage`__ shall be called to proceed with message encryption.
> __Important__: If PSK recipient was added in the message, the field `encryption.pub` shall point to the encryption public key.

The function returns the total message size in bytes or 0 if error occurred.

### Incoming Messages ###
Incoming message processing is also split into 2 stages: message parsing and message validating. Validating phase can be skipped if message is discarded by the upper layer.

#### Message parsing ####
Use __`FitSec_ParseMessage`__ to read the incoming message. It extracts the payload, sender position, timestamp, and security metadata (Signer type, SSP, certificates, or encryption keys).
The function shall be called with message information structure, containing following parameters:
- `message` - pointer to the incomming message buffer
- `messageSize` - size of the incomming message
- `generationTime` - the __current time__ to be used for cache processing.
- `payloadType` - (optional) payload type. If message payload type doesn't fit the requested one, the parsing is failed. Set to `FS_PAYLOAD_AUTO` to accept any type of payload.

The function will fill the content of the message information structure:
- `payload`, `payloadSize` and `payloadType` with actual information about the message payload
- `position` and `generationTime` with the sender position and time when message was sent if this information exists in the incomming message.
- `sign` contains additional information for signed message:
  - `signerType` - type of the signer (certificate, digest, or pre-shared key)
  - `ssp` - contains information about the application ID and service specific permissions
  - `cert` - signing certificate (if any)
- 'encryption' contains information about encrypted message:
  - `symm` - symmetric algorithm and encryption key
  - `cert` - certificate for message decryption
  - `priv` - private key or HSM key identifier to decrypt message if exists in the keys cache.

#### Message verification ####

After incomming message parsing, and the message type is set to _FS_PAYLOAD_SIGNED_ or _FS_PAYLOAD_SIGNED_EXTERNAL_, the upper layer can decide to verify message signature and validate conformance to the signing certificate restrictions, using functions __`FitSec_ValidateSignedMessage`__ or __`FitSec_ValidateSignedMessageAsync`__.

> __Important__: message verification procedure doesn't match the SSP bits with the content of facility payload. It is up to user to check the conformance of the incoming message with correspondent SSP bit fields and to use this message or skip it.

Validating function shall be called with message information structure, filled in by the message parsing function. Following fields should be set in the structure, depending of the `sign.signerType` value:
- `sign.cert` shall contain pointer to the `FSCertificate` if signer type is _FS_SI_DIGEST_ or _FS_SI_CERTIFICATE_.
- `sign.pub` shall contain pointer to the `FSPublicKey` if signer type is _FS_SI_SELF_.
- `sign.alg` shall be set to the actual signing algorithm if signer type is _FS_SI_SELF_.

Function returns true or false and set the error ID in the message information structure.

#### Message decrypting ####
The function __`FitSec_DecryptMessage`__ needs to be called to decrypt encrypted message if message type is set to _FS_PAYLOAD_ENCRYPTED_. 
The function shall be called with the following message information fields:
- `encryption`:
  - `cert` shall contain pointer to FSCertificate field containing description private key if recipient type is certificate. Parsing function sets this field if certificate is installed in the system.
  - `priv` shall contain the decryption private key if recipient key is PSK. The key is set to the proper value by the parsing function if the key is installed on the system.
- `generationTime` shall be set to the current time to manage key and certificate cache.

The function decrypts the payload, sets the payload size to the correct value and update the `encryption.symm` information field with symmetric key information.

The function returns size of the payload or 0 in case of error.

## CTL/CRL support ##

The library supports the CRL and CTL (ECTL) processing as defined in ETSI TS 102 941.

The CRL and CTL/ECTL message can be passed to the library using the __`FitSec_ApplyTrustInformationMessage`__ call. The message information field shall be filled in by the message parsing step. The function validates the message, so no needs to call __`FitSec_ValidateSignedMessage`__ explicitly.

There is a way to pass the raw data instead of already parsed message using the __`FitSec_ApplyTrustInformation`__ call, providing the data buffer containing OER representation of CTL or CRL.

> Pay attention, CRL/CTL signing certificate shall be already installed in the system.

There is also a way to request CRL/CTL information from distribution centres (DC) using the __`FitSec_RequestTrustInfo`__.

## PKI communication ##

PKI communication (enrolment and authorization) API is described in [fitsec_pki.h](fitsec_pki.h).

PKI submodule shall be initialized using __`FitSecPki_New`__ providing the following configuration elements of the `FitSecPkiConfig` structure:
- `station` shall contain ITS station identifiers, such as:
  - `id` and `id_len` contains canonical station identifier to be used for enrolment
  - `priv` points to the canonical private key to be used to sign enrolment requests
  - `alg` contains security algorithm of that private key
- `reqStorageDuration` contains duration in seconds to store PKI requests information after been sent. Set it to at least 10 seconds to let PKI servers do their job especially when certificate retransmission mechanism is used.

There are two functions to create outgoing PKI request: __`FitSecPki_PrepareECRequest`__ and __`FitSecPki_PrepareATRequest`__ and another two functions to process received responses: __`FitSecPki_loadMessage`__ and __`FitSecPki_loadData`__.

Outgoing request function takes the certificate request information and the message information as parameters and fills the message buffer in the message information structure with the actual certificate request message. It is up to upper layer to transmit this message to the PKI distribution centre using the known access point URL. 

The following message information fields shall be set for both calls:
- `message` and `messageSize` shall contain memory buffer and it size to store resulting message.

The access point URL can be associated with the CA certificate using CTL or manually using the __`FSCertificate_SetDC`__ and got back using the __`FSCertificate_GetDC`__ function.

### Enrolment ###
To trigger the enrolment procedure, the upper layer shall call __`FitSecPki_PrepareECRequest`__.

Function prepares the encrypted message in the provided message information structure, either using provided EA certificate in the `encryption.cert` field or selecting the proper EA automatically if this field is NULL.

The library can select EA certificate according to the provided requested certificates parameters.

Library will store the request hash internally to be able to proceed with the received answer.

### Authorization ###
Authorization request messages can be made using the __`FitSecPki_PrepareATRequest`__ function call.
The whole procedure is identical to the enrolment one.

## Limitations ##
- The library doesn't support the Butterfly Key Expansion mechanism, as described in ETSI TS 102 941 v2.x.x
- The library binaries have run-time limitations:
  - not more than 100 messages can be processed.
  - the library is working only during the year when it was compiled.

To remove all try-&-buy limitations ask author for the license.

## ToDo ##
- Misbehaviour reporting, as specified in ETSI TS 103 759
- CTL/CRL distribution, as specified in ETSI TS 103 601

## Author ##
The library was created and supported since 2015 by Denis Filatov (denis.filatov()fillabs.com) as a validation tool for the ETSI's ITS security test suite. The library is NOT a free product. Please contact author for the license.

