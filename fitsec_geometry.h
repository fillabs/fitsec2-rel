/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/
#ifndef fitsec_geometry_h
#define fitsec_geometry_h
#include <stdint.h>
#include <stdbool.h>

#include "fitsec_types.h"

typedef enum {
    FS_REGION_NONE,
    FS_REGION_CIRCLE,
    FS_REGION_RECTANGLE,
    FS_REGION_POLYGON,
    FS_REGION_ID,
    _FS_REGION_MAX,
} FSRegionType;
/*
typedef struct FSLocation {
    uint32_t latitude;
    uint32_t longitude;
}FSLocation;

typedef struct FS3DLocation {
    uint32_t latitude;
    uint32_t longitude;
    uint16_t evaluation;
}FS3DLocation;
*/
typedef struct FSGeoRegion FSGeoRegion;

FITSEC_EXPORT FSGeoRegion * FSGeo_New_Curcular(int32_t latitude, int32_t longitude, uint32_t radius);

FITSEC_EXPORT FSGeoRegion * FSGeo_New_Rectangular(void);
FITSEC_EXPORT bool          FSGeo_Rectangular_Add(FSGeoRegion * r, int32_t nw_latitude, int32_t nw_longitude,
                                    int32_t se_latitude, int32_t se_longitude);

FITSEC_EXPORT FSGeoRegion * FSGeo_New_Polygonal(size_t p_count, const int32_t * points);
FITSEC_EXPORT bool          FSGeo_Polygonal_Add(FSGeoRegion * r, int32_t latitude, int32_t longitude);

FITSEC_EXPORT FSGeoRegion * FSGeo_New_Identified(void);
FITSEC_EXPORT bool          FSGeo_Id_Add(FSGeoRegion *r, const uint16_t country, const uint8_t region, const uint16_t subregion);

FITSEC_EXPORT void          FSGeo_Free(FSGeoRegion * region);

FITSEC_EXPORT FSRegionType  FSGeo_RegionType(const FSGeoRegion* region);

FITSEC_EXPORT bool          FSGeo_IsLocationInside(const FSGeoRegion* where, int32_t latitude, int32_t longitude);
FITSEC_EXPORT bool          FSGeo_IsRegionInside  (const FSGeoRegion* where, const FSGeoRegion * inside);

#endif
