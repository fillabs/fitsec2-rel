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

#ifndef CUNUSED
#if defined(__GNUC__)
#define CUNUSED __attribute__((unused))
#define CDEPRECATED __attribute__((deprecated))
#elif defined (_MSC_VER)
#define CUNUSED
#define CDEPRECATED __declspec ((deprecated))
#else
#define CUNUSED
#define CDEPRECATED
#endif
#endif //CUNUSED

#ifdef __cplusplus
extern "C" {
#endif
    typedef uint32_t FSItsAid;
    typedef uint64_t FSHashedId8;
    typedef uint32_t FSHashedId3;

    static inline FSHashedId3 HashedId8toId3(FSHashedId8 id8) {
        return ((FSHashedId3*)&id8)[1]>>8;
    }
    static inline FSHashedId8 toHashedId8(const uint8_t * buf) {
            return *(FSHashedId8*)(buf);
	}
    FSHashedId3 toHashedId3(const uint8_t * buf);

    typedef uint64_t FSTime64;
    typedef uint32_t FSTime32;
    #define _FSTime32from64(t) ((uint32_t)(t/1000000))
    static inline FSTime32 FSTime32from64(FSTime64 t){
		return _FSTime32from64(t);
	}
    #define _FSTime64from32(t) (((uint64_t)t)*1000000) 
    static inline FSTime64 FSTime64from32(FSTime32 t){
		return _FSTime64from32(t);
	}

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

    typedef enum {
        FSEEApplication = 0x80,
        FSEEEnrollment = 0x40,
        FSEEAll = 0xC0
    }FSEEType;

    typedef struct FitSec FitSec;
    typedef struct FSCertificate FSCertificate;
    typedef struct FSMessageInfo FSMessageInfo;

#ifdef __cplusplus
}
#endif
#endif
