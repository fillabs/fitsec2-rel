/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/
#ifndef _FITSEC_TYPES_H_
#define _FITSEC_TYPES_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

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

#ifdef __cplusplus
extern "C" {
#endif
    typedef uint32_t FSItsAid;
    typedef uint64_t FSHashedId8;
    typedef uint32_t FSHashedId3;
    typedef uint64_t FSTime64;
    typedef uint32_t FSTime32;

    typedef struct FSLocation {
        int32_t latitude;
        int32_t longitude;
    }FSLocation;

    typedef struct FS3DLocation {
        int32_t      latitude;
        int32_t      longitude;
        uint16_t     elevation;
    } FS3DLocation;

    typedef struct FSTimeAndLocation {
        FSTime64 time;
        FS3DLocation location;
    }FSTimeAndLocation;

#define FS_SSP_MAX_LENGTH 32 // max 31 octet base on TS103097

    typedef union FSItsSsp {
        uint32_t opaque[FS_SSP_MAX_LENGTH / sizeof(uint32_t)]; // the length of SSP is limited to 31 octet in TS103097
        struct {
            unsigned char  version;
            unsigned char  flags[FS_SSP_MAX_LENGTH-1];
        }bits;
    }FSItsSsp;

    typedef struct {
        FSItsAid  aid;
        size_t    sspLen;
        FSItsSsp  sspData;
    } FSItsAidSsp;

    typedef struct FitSec FitSec;
    typedef struct FSCertificate FSCertificate;
    typedef struct FSMessageInfo FSMessageInfo;
    //typedef struct FitSecKey FitSecKey;
    //typedef struct FitSecSignature FitSecSignature;

    typedef enum {
        FS_SHA256,
        FS_SHA384,
        FS_SM3,

        FSCryptHashAlgorithm_Max
    }FSCryptHashAlgorithm;

#ifdef __cplusplus
}
#endif
#endif
