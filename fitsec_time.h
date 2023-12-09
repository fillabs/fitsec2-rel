/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/

#ifndef FITSEC_TIME_H
#define FITSEC_TIME_H

#include <time.h>
#ifndef _MSC_VER
#include <sys/time.h>
#endif
#include <inttypes.h>
#include "fitsec_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define ITS_UTC_EPOCH 1072915200

	FITSEC_EXPORT time_t mktaitime(struct tm *tim_p);
	FITSEC_EXPORT time_t addleapseconds(time_t t);
	FITSEC_EXPORT time_t removeleapseconds(time_t t);

	FITSEC_EXPORT struct tm * itstime(struct tm *tim_p, uint32_t t);
	FITSEC_EXPORT struct tm * itstime64(struct tm *tim_p, uint64_t t);
	FITSEC_EXPORT struct tm * taitime(struct tm *tim_p, time_t t);
	FITSEC_EXPORT struct tm * taitime64(struct tm *tim_p, uint64_t t);

	#define mktaitime32(X) ((uint32_t)mktaitime(X))
	FITSEC_EXPORT uint32_t mkitstime32(struct tm *tim_p);
	FITSEC_EXPORT uint32_t unix2itstime32(time_t t);
	
	FITSEC_EXPORT uint64_t mktaitime64(struct tm *tim_p);
	FITSEC_EXPORT uint64_t mkitstime64(struct tm *tim_p);
	FITSEC_EXPORT uint32_t unix2itstime32(time_t t);
	FITSEC_EXPORT uint64_t unix2itstime64(time_t t);
	#ifndef WIN32
	#define mkgmtime(TM) timegm(TM)
	#endif

	FITSEC_EXPORT int      timeval_subtract(struct timeval* result, const struct timeval* x, const struct timeval* y);
	FITSEC_EXPORT uint32_t timeval2itstime32(const struct timeval * tv);    
	FITSEC_EXPORT uint64_t timeval2itstime64(const struct timeval * tv);
	static inline uint32_t time32from64(uint64_t t){
		return (uint32_t)(t/1000000);
	}

	FITSEC_EXPORT const char * stritsdate32(uint32_t t);
	FITSEC_EXPORT const char * stritsdate64(uint64_t t);
	FITSEC_EXPORT const char * strtaidate(time_t t);
	FITSEC_EXPORT const char * strgmtdate(time_t t);
    FITSEC_EXPORT const char * stritstime64(uint64_t t);
    FITSEC_EXPORT const char * stritstime32(time_t t, uint32_t usec);
    FITSEC_EXPORT const char * strtaitime(time_t t, uint32_t usec);
    FITSEC_EXPORT const char * strgmttime(time_t t, uint32_t usec);
    FITSEC_EXPORT const char * strlocaltime(time_t t, uint32_t usec);

	typedef enum {
		dt_microseconds,
		dt_milliseconds,
		dt_seconds,
		dt_minutes,
		dt_hours,
		dt_sixtyHours,
		dt_years,

		__dt_max
	}duration_t;

	FITSEC_EXPORT uint32_t itstime32_add_duration(uint32_t t, duration_t dt, uint32_t v);
	FITSEC_EXPORT uint64_t itstime64_add_duration(uint64_t t, duration_t dt, uint32_t v);

#ifdef __cplusplus
}
#endif

#endif
