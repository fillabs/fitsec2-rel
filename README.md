# FITSec - The ITS Security implementation

## Overview ##

The FitSec library provides the security engine, implementing messages and certificates processing for Intelligent Transport Systems communication.

The library implements following specifications:
- [IEEE 1609.2-2022](https://standards.ieee.org/ieee/1609.2/10258/) - The main specification for ITS security message headers and certificate format
- [ETSI TS 103 097 v2.1.1](https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/02.01.01_60/ts_103097v020101p.pdf) - The ETSI profile for IEEE 1609.2
- [ETSI TS 102 941 v2.2.1](https://www.etsi.org/deliver/etsi_ts/102900_102999/102941/02.02.01_60/ts_102941v020201p.pdf) - The PKI communication (BFK support is ongoing).
- [ETSI TS 103 601 v2.2.1](https://www.etsi.org/deliver/etsi_ts/103600_103699/103601/01.01.01_60/ts_103601v010101p.pdf) - The CTL/CRL redistribution (support is ongoing).
- [ETSI TS 103 759 v2.1.1](https://www.etsi.org/deliver/etsi_ts/103700_103799/103759/02.01.01_60/ts_103759v020101p.pdf) - The misbehaviour reporting protocol (the support is ongoing).

The library can be used with any kind of communication protocol, particularly with the GeoNetworking as described in
[ETSI EN 302 636-4-1](http://www.etsi.org/deliver/etsi_en/302600_302699/3026360401/01.02.01_60/en_3026360401v010201p.pdf).

The library is written in plain C in cross-platform manner and has been compiled and tested in Linux(gcc) and Windows(mingw32,cygwin and Visual C 14) environments for x86 and ARM platforms.
The x86 Linux and Windows binaries with some limitations provided for testing purposes.

Try the library using the ITS message simulator: https://github.com/fillabs/fsmsggen

## Dependencies ##
Dependencies are collected using git submodules:
- [cshared](https://www.github.com/fillabs/cshared/) - The open-source library providing various utility functions
- [fscrypt](https://www.github.com/fillabs/fscrypt/) - The open-source library providing wrappers for various cryptographic engines. Currently following engines are implemented:
  - [OpenSSL](https://www.openssl.org/).
  - AutoTalk Craton2 HSM engine (not fully tested yet).
  - Other cryptographic engines can be implemented using the plugin API as described in fscrypt library README.

## User API ##
The main API is defined in the [_fitsec.h_](fitsec.h) header.
I'm strongly inviting you to have a look on this file to understand the meaning of various parameters.

### Initialization ###
First of all, the instance of the engine must be created using the __`FitSec_New`__.
This function takes a configuration structure of type _FitSecConfig_ as a parameter.

The _FitSecConfig_ contains the following configuration fields:
- __`version`__ - default protocol version. Set it to `3` according to IEEE 1609.2 and ETSI TS 103 097
- __`flags`__ - configuration flags bitmap. See the __`FitSecEngineFlags`__ data type for possible bit fields.
- __`appProfiles`__ - application profiles list, contains the array of type __`FitSecAppProfile`__. Each profile provides information for the outgoing message content and contains the following fields:
  - __`aid`__ - the ITS AID for the profile.
  - __`payloadType`__ - the message payload type to be used for outgoing messages
  - __`fields`__ - bitmap of necessary fields to be set in outgoing messages. See _`FitSecAppProfileFlags`_ for details.
  - __`certPeriod`__ - period in milliseconds when certificate shall be sent within the application message. Special values are:
    - `-1` - do not send any certificates and sign all messages using digest
    - `0` - send certificates within each outgoing message
    - use some positive value to send certificate in this time period after the previous message with certificate. For example set to 1000 to send certificate each second (default for CAM)
  - __`certChangePeriod`__ - the maximum duration when the AT certificate can be used before been changed to another one.
- __`encKeyStorageDuration`__ period in seconds when system keeps previously used symmetric key for decrypting incomming messages.
-__`storeTrustInformation`__ call user call-back to store received CA certificates, CRLs and CTLs.

Crypto engines:<br/>
The library provides a flexibility for using different crypto engines for different purposes. Crypto engines are referenced by their names. Two crypto engines are supported now: `openssl` and `atlk` (AutoTalk HSM library). Please have a look on cryptographic plugin definition in _fitsec_crypt_plugin.h_ and _fitsec_hash_plugin.h_.
- __`hashEngine`__ the crypto engine used for hash functions. currently "openssl" and "atlk" are supported, set to NULL for autoselect
- __`signEngine`__ the crypto engine for signing: "openssl", "atlk", NULL by default
- __`verifyEngine`__ the crypto engine for sugnature verification: "openssl", "atlk", NULL by default
- __`encryptEngine`__ the crypto engine for EC encrypting engine: "openssl", "atlk", NULL by default
- __`decryptEngine`__ the crypto engine for EC decryption: "openssl", "atlk", NULL by default
- __`symmEncryptEngine`__ the crypto engine for symmetric encryption: "openssl", "atlk", NULL by default
- __`symmDecryptEngine`__ the crypto engine for symmetric decryption: "openssl", "atlk", NULL by default
- __`macEngine`__ the crypto engine for MAC calculatoin: "openssl", "atlk", NULL by default
- __`randomEngine`__ the crypto engine for random function: "openssl", "atlk", NULL by default

Callbacks:<br/>
The library has two work modes: synchronous and asynchronous. In asynchronous mode the library interacts with the upper level using the set of callback functions. These callbacks are defined in the configuration structure:       
- __`cbOnSigned`__ user callback function to be called when the outgoing message is signed
- __`cbOnValidated`__ user callback function to be called when the incoming message is validated
- __`cbOnEncrypted`__ user callback function to be called when the outgoing message is encrypted
- __`cbOnDecrypted`__ user callback function to be called when the incoming message is decrypted
- __`cbOnEvent`__ user callback function to be called when some event is occurred (@see FSEventId)
- __`cbOnEventUser`__ user pointer to be passed to all callback functions

Certificate pool parameters:<br/>
- __`maxReceivedPoolSize`__ maximum size of the pool for AT certificates, installed in the system. 
- __`maxReceivedLifeTime`__ maximum life time of received AT certificates.
- __`purgePeriod`__ period in seconds when certificate pools must be purged. Set to 0 to do not purge at all. In this case two previous parameters doesn't make any sense.
- __`ctlCheckPeriod`__ period in seconds when the engine shall check for new CTLs. Shall be at least 24h for real usage.
- __`crlCheckPeriod`__ period in seconds when the engine shall check for new CRLs. Shall be at least 24h for real usage.

This configuration structure can be initialized using the __`FitSecConfig_InitDefault`__ and modified according to user's needs. Please have a look at the fitsec.h for the description of configuration fields.

Install all necessary certificates using function __`FitSec_InstallCertificate`__.
Any types of certificates can be installed: Root, TLM, EA, EC, AA, AT or any other custom certificate types.
Pay attention, that all root certificates installed by this function will be verified against itself and considered as trusted.
Authorization tickets shall be followed by the correspondent private keys or HSM key identifiers.

CTL/ECTL/CRL can also be installed. See [CTL/CRL support](#ctl-crl_support) chapter for information. 

Now the engine is ready to work. Upper layer can encode and decode messages.

### Outgoing Signed Messages ###
Processing of outgoing signed messages is split into two stages:
- preparation of the message header
- signing the message

In order to optimize the memory manipulation efforts, all message operations performed directly within the message buffer, provided by the facility layer.

This buffer, containing encoded message, can be passed later to the transport layer. The size of the buffer shall be well enough to contain all security headers, certificates and the payload of the message.

#### Usage with GeoNetworking messages ####
According to the GeoNetworking specification, the Security Header takes place between Basic GN Header and Common GN Header elements in GeoNetworking message structure.

So, to send a secured GN message, facility layer shall perform following actions:
- prepare Basic GN Header
- call __`FitSec_PrepareSignedMessage`__ to prepare Security header
- fill the payload buffer with the payload data, starting from Common GN Header
- update the payload size field in message information structure. 
  >(Note: Please don't spend too much time in this stage because it can violate the CAM signing rules.)
- call __`FitSec_FinalizeMessage`__ or __`FitSec_FinalizeSignedMessageAsync`__ to sign the message.

Please see the [_fitsec.h_](fitsec.h) for function descriptions.

#### Preparation of message header ####
To start encode the security envelop, the upper layer shall call __`FitSec_PrepareSignedMessage`__ to create the Security Header element and to put it into outgoing buffer.

This function must be called with the message information structure, containing following information:
- `message` and `messageSize` containing the outgoing buffer address and its size
- `payloadType` containing the necessary type of the security envelop: signed, encrypted, etc. _(optional, set to `FS_PAYLOAD_AUTO` by default)_. 
- `position` containing current geographic position if necessary. _(optional, not needed for CAM)_
- `generationTime` containing the timestamp when the last GPS fix has been occured.
- `sign` containing information about signing procedure. Following fields should be set:
  - `signerType` containing the type of signer. Set to `FS_SI_AUTO` to set the signer type automatically, according to the application. Other values to be used:
    - `FS_SI_CERTIFICATE` or `FS_SI_DIGEST` - use certificate or certificate digest to sign the message.
    
      Certificate can be provided in `sign.cert` field or can be selected automatically according to provided time, position and application id.
    - `FS_SI_SELF` - sign message using the private key provided in `sign.priv` field. 
    
      This field can be NULL in this stage but should be filled in with real value on the finalizing stage.
      The signing algorithm shell be specified in `sign.alg` field.
  - `ssp` containing application ID and SSP bits, describing the content of the message. The ITS AID list can be found on [ISO TS17419 V2016-02-09: "ITS-AID_AssignedNumbers"](http://standards.iso.org/iso/ts/17419/TS17419%20Assigned%20Numbers/TS17419_ITS-AID_AssignedNumbers.pdf)

The function creates the ITS Security Header in the provided buffer and fill the message information structure with:
- `payload` containing the pointer to the memory buffer where facility layer can fill with the payload data
- `payloadSize` containing the maximus size of the payload buffer
- `sign` containing data related to signing procedure:
  - `signerType` is set to the actual type of signer: `FS_SI_CERTIFICATE`, `FS_SI_DIGEST` or `FS_SI_SELF`
  - `cert` is set to the certificate to be used to sign message if `signerType` is set to the `FS_SI_CERTIFICATE` or `FS_SI_DIGEST`. This value can be changed before the final stage.

The data in the message information structure will be used on the next stage, so please keep it unchanged, excepts the payload size.
  
The function returns the offset in the buffer to copy the payload or 0 if case of some error. The error id and error description are provided in the message information structure.

Please see the [_fitsec.h_](fitsec.h) for function descriptions.

#### Preparing of payload ####

The GeoNetworking layer needs to create the Common Header and, optionally the Extended Header elements, and to put the facility layer payload into the outgoing buffer.

The total length of these elements shall be set in the payload size field in the message information structure.

#### Signing of the message ####
When the payload buffer is filled in, the message shall be signed or encrypted, according to the payload type.
The upper layer must call __`FitSec_FinalizeMessage`__ to perform these tasks. GN Layer can also call __`FitSec_FinalizeSignedMessageAsync`__ to perform asynchronous message signing.
This function takes same parameters as the __`FitSec_PrepareMessage`__.

The function returns the full size of secured packet or 0 in case of error. The error id and error description are provided in the message information structure.

### Outgoing Encrypted Messages ###
The library supports encryption based on IEEE 1609.2 specifications using algorithms defined in ETSI TS 103 097.
The encryption of the outgoing messages shall follow the same procedure as signing:
- preparation of the buffer using __`FitSec_PrepareEncryptedMessage`__
- adding one or more recipients.
- filling in the payload
- actual encryption using __`FitSec_FinalizeEncryptedMessage`__

#### Preparing of the encryption headers ####
The one should call the __`FitSec_PrepareEncryptedMessage`__ to initialize the outgoing buffer with the message header.
The function should be called with the message information structure, containing:
- `message` and `messageSize` containing the outgoing buffer address and its size
- `payloadType` containing the necessary type of the security envelop: signed, encrypted, etc. (optional, set to `FS_PAYLOAD_AUTO`) by default. 
- `generationTime` containing the timestamp, when the last GPS fix has been occured. This field is needed to select proper certificates and to process cached values.

#### Preparing of the encryption headers ####
The encrypted message can be addressed for up to 8 recipients. For the moment the library supports two types of encryption recipients: certificate or pre-shared keys (PSK). Not more than 1 PSK recipient is allowed.

To add a certificate as a recipient, the function __`FitSec_AddEncryptedMessageCertificateRecipient`__ shall be called with message information structure and the certificate id.

To add a PSK recipient, the __`FitSec_AddEncryptedMessagePSKRecipient`__ shall be called. The actual symmetric key can be set using the `symkey` parameter or it can be referenced using `digest` if the key was used recently and still exists in the key cache. The `encKeyStorageDuration` defines an encryption cache lifetime.

#### Preparing of payload ####
The payload to be encrypted shall be copied into the `payload` buffer.
The total length of the payload shall be set in the `payloadSize` field in the message information structure.

#### Finalize encryption ####
The actual encryption is the final step of the whole procedure. The function __`FitSec_FinalizeEncryptedMessage`__ shall be called to proceed with message encryption.
Be aware, if PSK recipient was added in the message, the field `encryption.pub` shall point to the encryption public key.

The function returns the total amount of bytes been used for the message or 0 if some error was occurred.

### Incoming Messages ###
Incoming message processing is also split into 2 stages: message reading and message validating. Validating phase can be skipped if message is discarded by the upper layer.

#### Message parsing ####
The function __`FitSec_ParseMessage`__ shall be used to read the incoming message.
The function shall be called with message information structure, containing following parameters:
- `message` - pointer to the message buffer
- `messageSize` - size of the message to parse
- `generationTime` - the current time to be used for cache processing.
- `payloadType` - can contain a type of the payload. If actual payload doesn't fit the requested one, the parsing is failed. Set to `FS_PAYLOAD_AUTO` to accept any type of payload.

The function will fill the content of the message information structure:
- `payload`, `payloadSize` and `payloadType` with actual information about the message payload
- `position` and `generationTime` with the sender position and time when message was sent if this information exists in the message.
- `sign` contains additional information for signed message:
  - `signerType` - type of the signer (certificate, digest, or pre-shared key)
  - `ssp` - contains information about the application ID and service specific permissions
  - `cert` - certificate been used for signing (if any)
- 'encryption' contains information about encrypted message:
  - `symm` - symmetric algorithm and encryption key
  - `cert` - certificate to be used to decrypt message
  - `priv` - private key to decrypt message if it was found in the keys cache.

#### Message verification ####
When signed message has been parsed and upper layer decided that this message makes sense, it can call __`FitSec_ValidateSignedMessage`__ or __`FitSec_ValidateSignedMessageAsync`__ 
to verify message signature and conformance to the signing certificate restrictions.

It is up to facility layer to check the conformance of the incoming message with correspondent SSP bit fields and to take this message into account or to skip it.

Function shall be called with message information structure, filled in by the message parsing function. Following fields should be set in the structure, depending of the `sign.signerType` value:
- `sign.cert` shall contain pointer to the `FSCertificate` if signer type is _FS_SI_DIGEST_ or _FS_SI_CERTIFICATE_.
- `sign.pub` shall contain pointer to the `FSPublicKey` if signer type is _FS_SI_SELF_.
- `sign.alg` shall be set to the actual signing algorithm if signer type is _FS_SI_SELF_.

Function returns true or false and fill the error id and the error description elements in the message information structure.

#### Message decrypting ####
The function __`FitSec_DecryptMessage`__ needs to be called to decrypt encrypted message.
The function shall be called with the following message information fields:
- `encryption`:
  - `cert` shall contain pointer to FSCertificate field containing description private key if recipient type is certificate. Parsing function sets this field if certificate is installed in the system.
  - `priv` shall contain the decryption private key if recipient key is PSK. The key is set to the proper value by the parsing function if the key is installed on the system.
- `generationTime` shall be set to the current time to manage key and certificate cache.

The function decrypts the payload, sets the payload size to the correct value and update the `encryption.symm` information field with symmetric key information.

The function returns size of the payload or 0 in case of error.

## CTL/CRL support ##

The library supports the CRL and CTL (ECTL) processing as defined in ETSI TS 102 941.

The CRL and CTL/ECTL message can be passed to the library using the __`FitSec_ApplyTrustInformationMessage`__ call. The message information field shall be filled in by the message parsing step. Function will validate the message, so no needs to call __`FitSec_ValidateSignedMessage`__ explicitly.

There is a way to pass the raw data instead of already parsed message using the __`FitSec_ApplyTrustInformation`__ call, providing the data buffer containing oer representation of CTL or CRL.

> Pay attention, CRL/CTL signer shall be already installed in the system.

There is also a way to request CRL/CTL information from distribution centres (DC) using the __`FitSec_RequestTrustInfo`__.

## PKI communication ##

PKI communication (enrolment and authorization) API is described in [fitsec_pki.h](fitsec_pki.h).

PKI submodule shall be initialized using __`FitSecPki_New`__ providing the following configuration elements of the `FitSecPkiConfig` structure:
- `station` shall contain ITS station identifiers, such as:
  - `id` and `id_len` contains canonical station identifier to be used for enrolment
  - `priv` points to the canonical private key to be used to sign enrolment requests
  - `alg` contains security algorithm of that private key
- `reqStorageDuration` contains duration in seconds to store PKI requests information after been sent. Set it to at least 10 seconds to let PKI servers do their job especially when certificate retransmission mechanism is used.

There are two functions to create outgoing PKI request: __`FitSecPki_PrepareECRequest`__ and __`FitSecPki_PrepareATRequest`__ and another two to process received responses: __`FitSecPki_loadMessage`__ and __`FitSecPki_loadData`__.

Outgoing request function takes the certificate request information and the message information as parameters and fills the message buffer in the message information structure with the actual certificate request message. It is up to upper layer to transmit this message to the PKI distribution centre using the proper access point URL. The access point URL can be associated with the CA certificate using CTL or manually using the `FSCertificate_SetDC` and got back using the `FSCertificate_GetDC` function.

The following message information fields shall be set for both calls:
- `message` and `messageSize` shall contain memory buffer and it size to store resulting message.

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
The library was crated and supported since 2015 by Denis Filatov (denis.filatov()fillabs.com) as a validation tool for the ETSI's ITS security test suite. The library is NOT a free product. Please contact author for the license.

