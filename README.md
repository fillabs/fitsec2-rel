# FITSec - The ITS Security implementation

## Overview ##

The FitSec library provides the security engine, implementing messages and certificates processing for Intelligent Transport Systems communication.

The library implements following specifications:
- [IEEE 1609.2-2022](https://standards.ieee.org/ieee/1609.2/10258/) - The main specification for ITS security message headers and certificate format
- [ETSI TS 103 097 v2.1.1](https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/02.01.01_60/ts_103097v020101p.pdf) - The ETSI profile for IEEE 1609.2
- [ETSI TS 102 941 v2.2.1](https://www.etsi.org/deliver/etsi_ts/102900_102999/102941/02.02.01_60/ts_102941v020201p.pdf) - The PKI communication (BFK support is ongoing).
- [ETSI TS 103 759 v2.1.1](https://www.etsi.org/deliver/etsi_ts/103700_103799/103759/02.01.01_60/ts_103759v020101p.pdf) - The misbehavior reporting protocol (suport is ongoing).

The library can be used with any kind of communication protocol, particularly with the GeoNetworking as described in
[ETSI EN 302 636-4-1](http://www.etsi.org/deliver/etsi_en/302600_302699/3026360401/01.02.01_60/en_3026360401v010201p.pdf).

The library is written in plain C in cross-platform manner and has been compiled and tested in Linux(gcc) and Windows(mingw32,cygwin and Visual C 13) environments for x86 and ARM platforms
The x86 Linux and Windows binaries with some limitations provided for testing purposes.

## Dependencies ##
Dependencies are collected using git submodules:
- [cshared](https://www.github.com/fillabs/cshared/) - The open-source library providing various utility functions
- [fscrypt](https://www.github.com/fillabs/fscrypt/) - The open-source library providing wrappers for varios cryptographic engines. Currently following engines are implemented:
  - [OpenSSL](https://www.openssl.org/).
  - AutoTalk Craton2 HSM engine (not fully tested yet).
  - Other cryptographic engines can be implemented using the plugin API as described in fscrypt library README.

## User API ##
The main API is defined in the [_fitsec.h_](fitsec.h) header.
I'm strongly inviting you to have a look on this file to understand the meaning of various parameters.

### Initialization ###
1. First of all, the instance of the engine must be created using the __*FitSec_New*__.
This function takes a configuration strucutre of type _FitSecConfig_ as a parameter.

The _FitSecConfig_ contains the following configuration fields:
- __`version`__ default protocol version. Set it to `3` according to IEEE 1609.2 and ETSI TS 103 097
- __`flags`__ configuration flags bitmap. See the _`FitSecEngineFlags`_ data type for possible bit fields.
- __`appProfiles`__ aplication profiles list, contains the array of type _`FitSecAppProfile`_. Each profile provides information for the outgoing message content and contains the following fields:
  - __`aid`__ the ITS AID for the profile.
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
- __`cbOnEvent`__ user callback function to be called when some event is occured (@see FSEventId)
- __`cbOnEventUser`__ user pointer to be passed to all callback functions

Certificate pool parameters:<br/>
- __`maxReceivedPoolSize`__ maximum size of the pool for AT certificates, installed in the system. 
- __`maxReceivedLifeTime`__ maximum life time of received AT certificates.
- __`purgePeriod`__ period in seconds when certificate pools must be purged. Set to 0 to do not purge at all. In this case two previous parameters doesn't make any sense.
- __`ctlCheckPeriod`__ period in seconds when the engine shall check for new CTLs. Shall be at least 24h for real usage.
- __`crlCheckPeriod`__ period in seconds when the engine shall check for new CRLs. Shall be at least 24h for real usage.

This configuration strucure can be initialized using the __*FitSecConfig_InitDefault*__ and modified according to user's needs. Please have a look at the fitsec.h for the description of configuration fields.

2. Install all necesary certificates using function __*FitSec_InstallCertificate*__.
Any types of certificates can be installed: Root, TLM, EA, EC, AA, AT or any other custom certificate types.
Pay attention, that all root certificates installed by this function will be verified against itself and considered as trusted.
Authorization tickets shall be followed by the correspondent private keys or HSM key idenifiers.

3. Now the engine is ready to work.

### Outgoing Signed Messages ###
Processing of outgoing signed messages is splitted to two stages:
- preparation of the message header
- signing the message

In order to optimize the memory manipulatoin efforts, all operations executes directly within the buffer provided by the facility layer.
This buffer can be passed later to the transport layer. The size of the buffer shall be well enough to contain all security headers,
certificates and the payload of the message.
According to the GeoNetworking specification, the Security Header takes place between Basic GN Header and Common GN Header elements in GeoNetworking message strucure.
So, to send a secured GN message, facylity layer shall perform following actions:
- prepare Basic GN Header
- call __*FitSec_PrepareSignedMessage*__ to prepare Security header
- fill the payload buffer with the payload data, starting from Common GN Header, update the payload size field in message information structure.
  (Note: Please don't spend too much time in this stage because it can violate the CAM signing rules.)
- call __*FitSec_FinalizeMessage*__ or __*FitSec_FinalizeSignedMessageAsync*__ to sign the message.

Please see the [_fitsec.h_](fitsec.h) for function descriptions.

#### Preparation of message header ####
As soon as GeoNetworking layer prepared the Basic Header, it can call __*FitSec_PrepareSignedMessage*__ to create the Security Header element and to put it into outgoing buffer.
This function must be called with the message information sctructure, containing following information:
- _message_ and _messageSize_ containing the outgoing buffer address and its size
- _payloadType_ containing the necessary type of the security envelop: signed, encrypted, etc. (optional, set to FS_PAYLOAD_AUTO) by default. 
- _position_ containing current geographic position if neccessary. (optional, not needed for CAM)
- _generationTime_ containing the timestamp, when the last GPS fix has been occured.
- __FIXIT__: Application ID and SSP bits, describing the content of the message. The ITS AID list can be found on [ISO TS17419 V2016-02-09: "ITS-AID_AssignedNumbers")(http://standards.iso.org/iso/ts/17419/TS17419%20Assigned%20Numbers/TS17419_ITS-AID_AssignedNumbers.pdf)

The function creates the ITS Security Header in the provided buffer and fill the message information structure with:
- payload offset - the pointer to the memory buffer where facility layer can put the payload
- max payload size - the maximum size of payload buffer. Facility layer shall put the actual payload size there
- certificate to be used - it takes into account provided ITS AID, SSP, timestamp and location
- signer type (certificate, digest, chain).

The function can override the payload type if it is required by the security profile. The CAM and DENM security profile requires the payload to be signed but not encrypted.

The data in the message information strucure will be used on the next stage, so please keep it unchanged, excepting of payload size.
  
The function returns the offset in the buffer to copy the payload or 0 if case of some error. The error id and error description are provided in the message information strucure.

Please see the [_fitsec.h_](fitsec.h) for function descriptions.

#### Preparing of payload ####

The GeoNetworking layer needs to create the Common Header and, optionally the Extended Header elements, and to put the facility layer payload into the outgoing buffer.

The total length of these elements shall be set in the payload size field in the message information strucure.

#### Signing of the message ####

When payload creation is well done, the message could be encrypted and/or signed, depending of the payload type.
The GN layer must call __*FitSec_FinalizeMessage*__ to perform these tasks. GN Layer can also call __*FitSec_FinalizeSignedMessageAsync*__ to perform asynchronous message signing.
This functions takes same parameters as the __*FitSec_PrepareMessage*__.

The function returns the full size of secured packet or 0 in case of error. The error id and error description are provided in the message information strucure.

### Outgoing Encrypted Messages ###


### Incoming Messages ###

The function __*FitSec_Verify*__ can be used to verify the incoming message signature.

It will fill the content of the message information structure:
- payload, payload size and payload type
- position and generation time
- signer info type and signing certificate (if any)
- Application ID and SSP bits of certificate.

Function verifies the message signature, returns true or false and fill the error id and the error description elements in the message information structure.

It is up to facility layer to check the conformance of the incoming message with correspondent SSP bitfield and to take or doesn't take it into account.

The function __*FitSec_Decrypt*__ will be implemented soon to be able to use encrypted messages.

## Limitations ##
- The library doesn't support implicit certificate validation.
- The library doesn't support the Butterfly Key Expansion mechanism, as described in ETSI TS 102 941 v2.x.x

## Author ##
The library was crated and supported since 2015 by Denis Filatov (denis.filatov()fillabs.com) as a validation tool for the ETSI's ITS security test suite. The library is NOT a free product. Please contact author for the license.
