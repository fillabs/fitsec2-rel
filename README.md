# FITSec - The ITS Security implementation

## Overview ##

The library provides the security envelop librariy to be used for the Intelligent Transport Systems communication.
Rhis communication can be based on the GeoNetworking protocol
[ETSI EN 302 636-4-1](http://www.etsi.org/deliver/etsi_en/302600_302699/3026360401/01.02.01_60/en_3026360401v010201p.pdf).
The library is fully conformed to [ETSI TS 103 097 v1.3.1 and later](http://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.03.01_60/ts_103097v010301p.pdf)

The library is written in plain C in cross-platform manner and has been compiled and tested in Linux(gcc) and Windows(mingw32,cygwin and Visual C 13) environments.

It implements the plugin interface to use various crypto engines. For the moment the following engines are implemented:
- [OpenSSL](https://www.openssl.org/)
- AutoTalk Craton2 HSM engine

Other crypto and hash engines can be implemented using the plugin API at _fitsec_hash_plugin.h_ and _fitsec_ecc_plugin.h_ 

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
  - __`certPeriod`__ - period in milliseconds when certificate shall be sent within the application message. Possible values are:
    - `-1` - to do not send certificates and sign messages using digest
    - `0` - to send certificates within each outgoing message
    - use some positive value to send certificate in this time period after the previous message with certificate. For example set to 1000 to send certificate each second (default for CAM)
  - __`certChangePeriod`__ - the maximum time to use the AT certificate.

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
- __`randomEngine` the crypto engine for random function: "openssl", "atlk", NULL by default

Callbacks:<br/>
The library has two work modes: synchronous and asynchronous. In asynchronous mode the library interacts with the upper level using the set of callback functions. These callbacks are defined in the configuration structure:       
- __`cbOnSigned`__ user callback function to be called when the outgoing message is signed
- __`cbOnValidated`__ user callback function to be called when the incoming message is validated
- __`cbOnEncrypted`__ user callback function to be called when the outgoing message is encrypted
- __`cbOnDecrypted`__ user callback function to be called when the incoming message is decrypted
- __`cbOnEvent`__ user callback function to be called when some event is occured (@see FSEventId)
- __`cbOnEventUser`__ user pointer to be passed to all callback functions

Certificate pool parameters:<br/>
- __`maxReceivedPoolSize`__ maximum size of received AT certificate pool
- __`maxReceivedLifeTime`__ maximum life time of received certificate
- __`purgePeriod`__ period in seconds when certificate pools must be purged. Set to 0 to do not purge

This configuration strucure can be initialized using the __*FitSecConfig_InitDefault*__ and modified according to user's needs. Please have a look at the fitsec.h for the description of configuration fields.

2. Install all necesary certificates using function __*FitSec_InstallCertificate*__.
Any types of certificates can be installed: Root, TLM, EA, EC, AA, AT or other type if any.
All root certificates installed by this function will be verified against itself and considered as trusted.
Authorization tickets shall be followed by the correspondent private keys or HSM key idenifiers.

3. After installation, all certificates shall be validated against their issuers. The __*FitSec_RelinkCertificates*__ function shall be run when all necessary certificates were installed.

### Outgoing Signed Messages ###
Processing of outgoing signed messages is splitted to two stages:
- preparation of the message header
- signing of the message

In order to optimize the memory manipulatoin efforts, all operations executes directly with the buffer provided by the facility layer.
This buffer can be passed later to the transport layer. The size of the buffer shall be well enough to contain all security headers,
certificates and the payload of the message.
The GeoNetworking Security Header takes place between Basic Header and Common Header elements in GeoNetworking message strucure.
So, to send a secured GN message, facylity layer shall perform following actions:
- prepare Basic GN Header
- call __*FitSec_PrepareSignedMessage*__ to prepare Security header
- fill the payload buffer with the payload data, starting from Common GN Header, update the payload size field in message information structure.
  (Note: Please don't spend too much time in this stage because it can violate the CAM signing rules.)
- call __*FitSec_SignMessage*__ to encrypt and/or sign the message.

Please see the [_fitsec.h_](libfitsec/fitsec.h) for function descriptions.

#### Preparation of message header ####
As soon as GeoNetworking layer prepared the Basic Header, it can call __*FitSec_PrepareMessage*__ to create the Security Header element and to put it into outgoing buffer.
This function must be called with following parameters:
- buffer and maximum buffer length. This parameter shall point to the outgoing memory buffer right after the Basic Header element.
- message information strucuture, containing:
  - payload type (signed, encrypted, etc.)
  - current position (not needed for CAM)
  - the timestamp, when the last GPS fix has been occured.
  - Application ID and SSP bits, describing the content of the message. The ITS AID list can be found on [ISO TS17419 V2016-02-09: "ITS-AID_AssignedNumbers")(http://standards.iso.org/iso/ts/17419/TS17419%20Assigned%20Numbers/TS17419_ITS-AID_AssignedNumbers.pdf)

The function creates the ITS Security Header in the provided buffer and fill the message information structure with:
- payload offset - the pointer to the memory buffer where facility layer can put the payload
- max payload size - the maximum size of payload buffer. Facility layer shall put the actual payload size there
- certificate to be used - it takes into account provided ITS AID, SSP, timestamp and location
- signer type (certificate, digest, chain).

The function can override the payload type if it is required by the security profile. The CAM and DENM security profile requires the payload to be signed but not encrypted.

The data in the message information strucure will be used on the next stage, so please keep it unchanged, excepting of payload size.
  
The function returns the offset in the buffer to copy the payload or -1 if case of some error. The error id and error description are provided in the message information strucure.

Please see the [_fitsec.h_](libfitsec/fitsec.h) for function descriptions.

#### Preparing of payload ####
The GeoNetworking layer needs to create the Common Header and, optionally the Extended Header elements, and to put the facility layer payload into the outgoing buffer.

The total length of these elements shall be set in the payload size field in the message information strucure.

#### Signing and/or encrypting of the message ####

When payload creation is well done, the message could be encrypted and/or signed, depending of the payload type.
The GN layer must call __*FitSec_SignMessage*__ to perform these tasks.
This functions takes same parameters as the __*FitSec_PrepareMessage*__.

_Note: encryption is not implemented yet. See Limitations section_

The function returns the full size of secured packet or -1 in case of error. The error id and error description are provided in the message information strucure.

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
- The library doesn't support encryption for the moment.

## Author ##
The library was created in 2015-2016 by Denis Filatov (danya.filatov()gmail.com) in order to validate the ETSI's ITS security test suite. The library is free for non-commercial and not-for-profit usage, otherwise please contact the author.
