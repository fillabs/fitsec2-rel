/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/

#include "../fitsec_geometry.h"
#include "cmem.h"

#include <math.h>

typedef struct {
    FSLocation center;
    uint32_t   radius;
} FSCircularRegion;

typedef struct {
    FSLocation nw;
    FSLocation se;
}FSRectangle;

typedef struct {
    size_t count;
    FSRectangle r[8];
} FSRectangularRegion;

typedef struct {
    size_t count;
    FSLocation points[12];
} FSPolygonalRegion;

typedef struct {
    uint8_t  region;
    size_t   srcount;
    uint16_t subregions[8];
}FSIdentifiedRegionItemRegion;

typedef struct {
    uint16_t  country;
    size_t    rcount;
    FSIdentifiedRegionItemRegion regions[8];
}FSIdentifiedRegionItem;

typedef struct {
    size_t count;
    FSIdentifiedRegionItem r[8];
} FSIdentifiedRegion;

typedef union {
    FSCircularRegion      circular;
    FSRectangularRegion   rectangular;
    FSPolygonalRegion     polygonal;
    FSIdentifiedRegion    identified;
}FSGeoRegionUnion;

struct FSGeoRegion {
    FSRegionType type;
    FSGeoRegionUnion u;
} ;
/*
static inline uint32_t _int32_abs(const int32_t v) {
    register int32_t y = v >> 31;
    return (y ^ v) - y;
}

static inline bool is_valid_latitude(const int32_t l) {
    return _int32_abs(l) < 900000000;
}

static inline bool is_valid_longitude(const int32_t l) {
    return _int32_abs(l) < 1800000000;
}
static inline bool is_valid_point(const int32_t lat, const int32_t lon) {
    return is_valid_latitude(lat) && is_valid_longitude(lon);
}
*/
FSGeoRegion* FSGeo_New_Curcular(int32_t latitude, int32_t longitude, uint32_t radius)
{
    FSGeoRegion* r = cnew(FSGeoRegion);
    if(r){
        r->type = FS_REGION_CIRCLE;
        r->u.circular.center.latitude = latitude;
        r->u.circular.center.longitude = longitude;
        r->u.circular.radius = radius;
    }
    return r;
}

FSGeoRegion * FSGeo_New_Rectangular(void)
{
    FSGeoRegion * r = cnew(FSGeoRegion);
    if (r) {
        r->type = FS_REGION_RECTANGLE;
        r->u.rectangular.count = 0;
    }
    return r;
}

bool FSGeo_Rectangular_Add(FSGeoRegion * r, int32_t nw_latitude, int32_t nw_longitude,
    int32_t se_latitude, int32_t se_longitude)
{
    if(r->type == FS_REGION_RECTANGLE){
        if ((nw_latitude - se_latitude) && (nw_longitude - se_longitude)) {
            if (r->u.rectangular.count < (sizeof(r->u.rectangular.r) / sizeof(r->u.rectangular.r[0]))) {
                r->u.rectangular.r[r->u.rectangular.count].nw.latitude = nw_latitude;
                r->u.rectangular.r[r->u.rectangular.count].nw.longitude = nw_longitude;
                r->u.rectangular.r[r->u.rectangular.count].se.latitude = se_latitude;
                r->u.rectangular.r[r->u.rectangular.count].se.longitude = se_longitude;
                r->u.rectangular.count++;
                return true;
            }
        }
    }
    return false;
}

FSGeoRegion * FSGeo_New_Polygonal(size_t pcount, const int32_t * points)
{
    FSGeoRegion * r = cnew(FSGeoRegion);
    if (r) {
        r->type = FS_REGION_POLYGON;
        if (pcount > sizeof(r->u.polygonal.points) / sizeof(r->u.polygonal.points[0]))
            pcount = sizeof(r->u.polygonal.points) / sizeof(r->u.polygonal.points[0]);
        r->u.polygonal.count = pcount;
        for (size_t i = 0; i < pcount; i++) {
            r->u.polygonal.points[i].latitude = points[i * 2];
            r->u.polygonal.points[i].longitude = points[i * 2 + 1];
        }
    }
    return r;
}
bool FSGeo_Polygonal_Add(FSGeoRegion * r, int32_t latitude, int32_t longitude)
{
    if (r->type == FS_REGION_POLYGON) {
        if (r->u.polygonal.count + 1 < sizeof(r->u.polygonal.points) / sizeof(r->u.polygonal.points[0])) {
            r->u.polygonal.points[r->u.polygonal.count].latitude = latitude;
            r->u.polygonal.points[r->u.polygonal.count].longitude = longitude;
            r->u.polygonal.count++;
            return true;
        }
    }
    return false;
}

FSGeoRegion * FSGeo_New_Identified()
{
    FSGeoRegion * r = cnew(FSGeoRegion);
    if (r) {
        r->type = FS_REGION_ID;
        r->u.identified.count = 0;
    }
    return r;
}

// bool FSGeo_Id_Add(FSGeoRegion *r, uint16_t country, size_t rcount, const uint8_t * regions)
bool FSGeo_Id_Add(FSGeoRegion* r, const uint16_t country, const uint8_t region, const uint16_t subregion)
{
    int i;
    if(r->type != FS_REGION_ID)
        return false;

    FSIdentifiedRegionItem * ri;
    // looking for country starting from the end
    for(i = ((int)r->u.identified.count) - 1; i >= 0; i--){
        if(r->u.identified.r[i].country == country){
            ri = &r->u.identified.r[i];
            break;
        }
    }
    if (i < 0) {
        if (r->u.identified.count >= sizeof(r->u.identified.r) / sizeof(r->u.identified.r[0]))
            return false;
        ri = r->u.identified.r + r->u.identified.count;
        ri->country = country;
        ri->rcount = 0;
    }

    if (region != 0) {
        // looking for the region
        FSIdentifiedRegionItemRegion* rir;
        for (i = ((int)ri->rcount) - 1; i >= 0; i--) {
            if (ri->regions[i].region == region) {
                rir = ri->regions + i;
                break;
            }
        }
        if (i < 0) {
            if (ri->rcount >= sizeof(ri->regions) / sizeof(ri->regions[0]))
                return false;
            rir = ri->regions + ri->rcount;
            rir->region = region;
            rir->srcount = 0;
        }
        if (subregion) {
            // looking for subregion
            for (i = ((int)rir->srcount) - 1; i >= 0; i--) {
                if (rir->subregions[i] == subregion)
                    return true;
            }
            if (rir->srcount >= sizeof(rir->subregions) / sizeof(rir->subregions[0])) {
                return false;
            }
            rir->subregions[rir->srcount++] = subregion;
        }
        if (rir - &ri->regions[0] == ri->rcount) {
            ri->rcount++;
        }
    }
    if (ri - &r->u.identified.r[0] == r->u.identified.count) {
        r->u.identified.count++;
    }
    return true;
}

void          FSGeo_Free(FSGeoRegion * region)
{
    if(region)
        cfree(region);
}

FSRegionType  FSGeo_RegionType(const FSGeoRegion* region)
{
    return region->type;
}

typedef bool (*FSGeo_IsLocationInside_Fn) (const void* u, const FSLocation * l);

static  bool _None_IsLocationInside (const FSCircularRegion * r, const FSLocation * l);
static  bool _Circle_IsLocationInside (const FSCircularRegion * r, const FSLocation * l);
static  bool _Rectangle_IsLocationInside (const FSRectangularRegion* r, const FSLocation * l);
static  bool _Polygon_IsLocationInside (const FSPolygonalRegion* r, const FSLocation * l);
static  bool _Id_IsLocationInside (const FSIdentifiedRegion* r, const FSLocation * l);

static FSGeo_IsLocationInside_Fn _IsLocationInside[] = {
    (FSGeo_IsLocationInside_Fn)_None_IsLocationInside,
    (FSGeo_IsLocationInside_Fn)_Circle_IsLocationInside,
    (FSGeo_IsLocationInside_Fn)_Rectangle_IsLocationInside,
    (FSGeo_IsLocationInside_Fn)_Polygon_IsLocationInside,
    (FSGeo_IsLocationInside_Fn)_Id_IsLocationInside
};

bool FSGeo_IsLocationInside(const FSGeoRegion* where, int32_t latitude, int32_t longitude)
{
	FSLocation l = {
		latitude,
		longitude
	};
    return _IsLocationInside[where->type] (&where->u, &l);
}

static const double _DEG_TO_RAD = 0.017453292519943295769236907684886;
static const double _EARTH_RADIUS_IN_METERS = 6372797.560856;
//static const double _LAT_DEGREE_IN_METERS = 111134.8555555556;
static const int32_t _LAT_ITS_IN_ONE_METTER = 90;

/*
static const double _PI = 3.141592653589793;
static const double _2PI = 6.283185307179586;
*/

static inline double its2degree(int32_t v){
    return ((double)v) / 10000000.0;
}

static inline int32_t degree2its(double d) {
    return (int32_t)floor((d * 10000000.0) + 0.5);
}

static uint32_t _FSLocation_Distance(const FSLocation * l, const FSLocation * p)
{
    double lat1, lon1, lat2, lon2;
    lat1 = its2degree(l->latitude) * _DEG_TO_RAD;
    lon1 = its2degree(l->longitude) * _DEG_TO_RAD;
    lat2 = its2degree(p->latitude) * _DEG_TO_RAD;
    lon2 = its2degree(p->longitude) * _DEG_TO_RAD;

    double latitudeArc = lat1 - lat2;
    double longitudeArc = lon1 - lon2;
//	if (longitudeArc > _PI)  longitudeArc = _2PI - longitudeArc;
//	if (longitudeArc < 0.0-_PI) longitudeArc = _2PI + longitudeArc;
    
    double latitudeH = sin(latitudeArc * 0.5);
    latitudeH *= latitudeH;
    double lontitudeH = sin(longitudeArc * 0.5);
    lontitudeH *= lontitudeH;
    double tmp = cos(lat1) * cos(lat2);
    return (uint32_t) (0.5 + 2.0 * _EARTH_RADIUS_IN_METERS * asin(sqrt(latitudeH + tmp*lontitudeH)));
}


static  bool _None_IsLocationInside (const FSCircularRegion * r, const FSLocation * l)
{
    return true;
}

static  bool _Circle_IsLocationInside (const FSCircularRegion * r, const FSLocation * l)
{
    uint32_t distance = _FSLocation_Distance(&r->center, l);
    return (distance <= r->radius);
}

static bool _IsLocationInsideRectangle(const FSRectangle* r, const FSLocation* l)
{
    if (r->nw.latitude >= l->latitude && r->se.latitude <= l->latitude) {
        if (r->nw.longitude < r->se.longitude) {
            if (l->longitude >= r->nw.longitude && l->longitude <= r->se.longitude)
                return true;
        }
        else {
            int32_t lw, le, ll;
            lw = r->nw.longitude - 1800000000;
            le = r->se.longitude + 1800000000;
            ll = (l->longitude > 0) ? l->longitude - 1800000000 : 1800000000 + l->longitude;
            if (ll >= lw && ll <= le)
                return true;
        }
    }
    return false;
}

static bool _IsRectangleInsideRectangle(const FSRectangle* r, const FSRectangle* l)
{
    if (r->nw.latitude >= l->nw.latitude && r->se.latitude <= l->se.latitude) {
        if (r->nw.longitude < r->se.longitude) {
            if (l->nw.longitude >= r->nw.longitude && l->se.longitude <= r->se.longitude)
                return true;
        }
        else {
            int32_t rw, re, lw, le;
            rw = r->nw.longitude - 1800000000;
            re = r->se.longitude + 1800000000;
            lw = (l->nw.longitude > 0) ? l->nw.longitude - 1800000000 : 1800000000 + l->nw.longitude;
            le = (l->se.longitude > 0) ? l->se.longitude - 1800000000 : 1800000000 + l->se.longitude;
            if (lw >= rw && le <= re)
                return true;
        }
    }
    return false;
}

static bool _IsRectangleInsideRectangularRegion(const FSRectangularRegion* r, const FSRectangle* l)
{
    for (size_t i = 0; i < r->count; i++) {
        if (_IsRectangleInsideRectangle(&r->r[i], l))
            return true;
    }
    return false;
}

static  bool _Rectangle_IsLocationInside (const FSRectangularRegion* r, const FSLocation * l)
{
    // check that l is in at least one rectangle;
    for (size_t n = 0; n < r->count; n++) {
        if (_IsLocationInsideRectangle(&r->r[n], l))
            return true;
    }
    return false;
}

/*
static int _FSLocation_IsLeft(const FSLocation * P0, const FSLocation * P1, const FSLocation * P2)
{
    return
        ((P1->longitude < P0->longitude) ? -1 : 1) *
        ((P2->latitude < P0->latitude) ? -1 : 1) *
        ((P2->longitude < P0->longitude) ? -1 : 1) *
        ((P1->latitude < P0->latitude) ? -1 : 1);
}
*/
static int _check_cross(const FSLocation* p1, const FSLocation* p2, const FSLocation* l)
{
    int32_t y = (l->longitude - p1->longitude) * (p2->latitude - p1->latitude) / (p2->longitude - p1->longitude) + p1->latitude;
    int32_t minx, maxx;
    if(p1->longitude > p2->longitude) {
    	minx = p2->longitude; maxx = p1->longitude;
    } else {
    	minx = p1->longitude; maxx = p2->longitude;
    }
    return (p1->longitude != p2->longitude) && (l->latitude >= y) && (l->longitude > minx) && (l->longitude <= maxx);
}

static  bool _Polygon_IsLocationInside(const FSPolygonalRegion* r, const FSLocation* l)
{
    size_t i, wn = 0, pcount = r->count;
    const FSLocation* points = &r->points[0];

    wn = _check_cross(&points[pcount - 1], &points[0], l);
    for (i = 0; i < pcount - 1; i++) {
        wn += _check_cross(&points[i], &points[i + 1], l);
    }
    return (wn & 1);
/*
    // loop through all edges of the polygon
    for (i = 0; i < pcount; i++)
    {// edge from V[i] to V[i+1]
        // loop through all edges of the polygon
        if (points[i].latitude <= l->latitude) {   // start y <= P.y
            if (points[(i + 1) % pcount].latitude > l->latitude)      // an upward crossing
               if (_FSLocation_IsLeft(&points[i], &points[(i + 1) % pcount], l) > 0) // P left of edge
                   ++wn;            // have a valid up intersect
        }
        else {   // start y > P.y (no test needed)
            if (points[(i + 1) % pcount].latitude <= l->latitude) // a downward crossing
                if (_FSLocation_IsLeft(&points[i], &points[(i + 1) % pcount], l) < 0) // P right of edge
                    --wn;            // have a valid down intersect
        }
    }
    return (wn != 0);
*/
}

static  bool _Id_IsLocationInside (const FSIdentifiedRegion* r, const FSLocation * l)
{
    // TODO: write this
    return true;
}

typedef bool(*FSGeo_IsRegionInside_Fn) (const void* r, const void * s);

static  bool _IsNoneContainsAny(const void * r, const void * s);
static  bool _IsAnyContainsNone(const void * r, const void * s);

static  bool _IsCircleContainsCircle(const FSCircularRegion * r, const FSCircularRegion * s);
static  bool _IsCircleContainsRectangle(const FSCircularRegion * r, const FSRectangularRegion * s);
static  bool _IsCircleContainsPolygon(const FSCircularRegion * r, const FSPolygonalRegion * s);
static  bool _IsCircleContainsId(const FSCircularRegion * r, const FSIdentifiedRegion * s);

static  bool _IsRectangleContainsCircle(const FSRectangularRegion * r, const FSCircularRegion * l);
static  bool _IsRectangleContainsRectangle(const FSRectangularRegion * r, const FSRectangularRegion * l);
static  bool _IsRectangleContainsPolygon(const FSRectangularRegion * r, const FSPolygonalRegion * l);
static  bool _IsRectangleContainsId(const FSRectangularRegion * r, const FSIdentifiedRegion * l);

static  bool _IsPolygonContainsCircle(const FSPolygonalRegion * r, const FSCircularRegion * l);
static  bool _IsPolygonContainsRectangle(const FSPolygonalRegion * r, const FSRectangularRegion * l);
static  bool _IsPolygonContainsPolygon(const FSPolygonalRegion * r, const FSPolygonalRegion * l);
static  bool _IsPolygonContainsId(const FSPolygonalRegion * r, const FSIdentifiedRegion * l);

static  bool _IsIdContainsCircle(const FSIdentifiedRegion * r, const FSCircularRegion * l);
static  bool _IsIdContainsRectangle(const FSIdentifiedRegion * r, const FSRectangularRegion * l);
static  bool _IsIdContainsPolygon(const FSIdentifiedRegion * r, const FSPolygonalRegion * l);
static  bool _IsIdContainsId(const FSIdentifiedRegion * r, const FSIdentifiedRegion * l);

static FSGeo_IsRegionInside_Fn _IsRegionInside[] = {
    (FSGeo_IsRegionInside_Fn)_IsNoneContainsAny,
    (FSGeo_IsRegionInside_Fn)_IsNoneContainsAny,
    (FSGeo_IsRegionInside_Fn)_IsNoneContainsAny,
    (FSGeo_IsRegionInside_Fn)_IsNoneContainsAny,
    (FSGeo_IsRegionInside_Fn)_IsNoneContainsAny,

    (FSGeo_IsRegionInside_Fn)_IsAnyContainsNone,
    (FSGeo_IsRegionInside_Fn)_IsCircleContainsCircle,
    (FSGeo_IsRegionInside_Fn)_IsCircleContainsRectangle,
    (FSGeo_IsRegionInside_Fn)_IsCircleContainsPolygon,
    (FSGeo_IsRegionInside_Fn)_IsCircleContainsId,

    (FSGeo_IsRegionInside_Fn)_IsAnyContainsNone,
    (FSGeo_IsRegionInside_Fn)_IsRectangleContainsCircle,
    (FSGeo_IsRegionInside_Fn)_IsRectangleContainsRectangle,
    (FSGeo_IsRegionInside_Fn)_IsRectangleContainsPolygon,
    (FSGeo_IsRegionInside_Fn)_IsRectangleContainsId,

    (FSGeo_IsRegionInside_Fn)_IsAnyContainsNone,
    (FSGeo_IsRegionInside_Fn)_IsPolygonContainsCircle,
    (FSGeo_IsRegionInside_Fn)_IsPolygonContainsRectangle,
    (FSGeo_IsRegionInside_Fn)_IsPolygonContainsPolygon,
    (FSGeo_IsRegionInside_Fn)_IsPolygonContainsId,

    (FSGeo_IsRegionInside_Fn)_IsAnyContainsNone,
    (FSGeo_IsRegionInside_Fn)_IsIdContainsCircle,
    (FSGeo_IsRegionInside_Fn)_IsIdContainsRectangle,
    (FSGeo_IsRegionInside_Fn)_IsIdContainsPolygon,
    (FSGeo_IsRegionInside_Fn)_IsIdContainsId,
};

bool          FSGeo_IsRegionInside  (const FSGeoRegion* where, const FSGeoRegion * inside)
{
    return _IsRegionInside[where->type*_FS_REGION_MAX + inside->type] (&where->u, &inside->u);
}

static  bool _IsNoneContainsAny(const void * r, const void * s)
{
    return true;
}

static  bool _IsAnyContainsNone(const void * r, const void * s)
{
    return false;
}

static  bool _IsCircleContainsCircle(const FSCircularRegion * r, const FSCircularRegion * s)
{
    return (_FSLocation_Distance(&r->center, &s->center) + s->radius <= r->radius);
}

static  bool _IsCircleContainsRectangle(const FSCircularRegion * r, const FSRectangularRegion * s)
{
    // true if all points of all rectangles are inside the circle
    for (size_t i = 0; i < s->count; i++) {
        FSLocation tmp;
        if (_FSLocation_Distance(&r->center, &s->r[i].nw) > r->radius) {
            return false;
        }
        if (_FSLocation_Distance(&r->center, &s->r[i].se) > r->radius) {
            return false;
        }
        tmp.latitude = s->r[i].nw.latitude;
        tmp.longitude = s->r[i].se.longitude;
        if (_FSLocation_Distance(&r->center, &tmp) > r->radius) {
            return false;
        }
        tmp.latitude = s->r[i].se.latitude;
        tmp.longitude = s->r[i].nw.longitude;
        if (_FSLocation_Distance(&r->center, &tmp) > r->radius) {
            return false;
        }
    }
    return true;
}

static  bool _IsCircleContainsPolygon(const FSCircularRegion * r, const FSPolygonalRegion * s)
{
    // check that all points are inside circle
    for (size_t i = 0; i < s->count; i++) {
        if (_FSLocation_Distance(&r->center, &s->points[i]) > r->radius) {
            return false;
        }
    }
    return true;
}

static  bool _IsCircleContainsId(const FSCircularRegion * r, const FSIdentifiedRegion * s)
{
    // TODO: shell be done using geolocalization
    return true;
}

static int32_t _mettersToLongitude(double meters, int32_t latitude)
{
    return degree2its(meters / (1113200.0 * cos(its2degree(latitude) * _DEG_TO_RAD)));
}

static int32_t _mettersToLatitude(int32_t meters)
{
    return _LAT_ITS_IN_ONE_METTER * meters;
}

static  bool _IsRectangleContainsCircle(const FSRectangularRegion * r, const FSCircularRegion * c)
{
    FSRectangle cr;
    int32_t r_lat = _mettersToLatitude(c->radius);
    int32_t r_lon = _mettersToLongitude(c->radius, c->center.latitude);
    cr.nw.latitude = c->center.latitude + r_lat;
    cr.se.latitude = c->center.latitude - r_lat;
    cr.nw.longitude = c->center.longitude - r_lon;
    cr.se.longitude = c->center.longitude + r_lon;

    // Circle shall be inside the one of rectangles
    return _IsRectangleInsideRectangularRegion(r, &cr);
}

static  bool _IsRectangleContainsRectangle(const FSRectangularRegion * r, const FSRectangularRegion * s)
{
    // each rectanle of s shall be inside the one of r
    for (size_t si = 0; si < s->count; si++) {
        if (!_IsRectangleInsideRectangularRegion(r, &s->r[si]))
            return false;
    }
    return true;
}

static  bool _IsRectangleContainsPolygon(const FSRectangularRegion * r, const FSPolygonalRegion * s)
{
    for (size_t ri = 0; ri < r->count; ri++) {
        size_t i;
        for (i = 0; i < s->count; i++) {
            if (!_IsLocationInsideRectangle(&r->r[ri], &s->points[i])) {
                break;
            }
        }
        if (i == s->count) return true;
    }
    return false;
}

static  bool _IsRectangleContainsId(const FSRectangularRegion * r, const FSIdentifiedRegion * s)
{
    // TODO: shell be done using geolocalization
    return false;
}

static  bool _IsPolygonContainsCircle(const FSPolygonalRegion * r, const FSCircularRegion * s)
{
    //TODO: check that polygon contains circle
    return false;
}
static  bool _IsPolygonContainsRectangle(const FSPolygonalRegion * r, const FSRectangularRegion * s)
{
    //TODO: convert rectangle to polygon and check that one polygon is inside another
    return false;
}
static  bool _IsPolygonContainsPolygon(const FSPolygonalRegion * r, const FSPolygonalRegion * s)
{
    //TODO: check that one polygon is inside another
    return false;
}
static  bool _IsPolygonContainsId(const FSPolygonalRegion * r, const FSIdentifiedRegion * s)
{
    // TODO: shell be done using geolocalization
    return false;
}

static  bool _IsIdContainsCircle(const FSIdentifiedRegion * r, const FSCircularRegion * s)
{
    // TODO: shell be done using geolocalization
    return false;
}
static  bool _IsIdContainsRectangle(const FSIdentifiedRegion * r, const FSRectangularRegion * s)
{
    // TODO: shell be done using geolocalization
    return false;
}
static  bool _IsIdContainsPolygon(const FSIdentifiedRegion * r, const FSPolygonalRegion * s)
{
    // TODO: shell be done using geolocalization
    return false;
}
static  bool _IsIdContainsId(const FSIdentifiedRegion * r, const FSIdentifiedRegion * s)
{
    size_t i, j;
    const FSIdentifiedRegionItem *ri, *si;

    for (i = 0; i < s->count; i++) {
        si = &s->r[i];
        // looking for the country item
        for (j = 0; j < r->count; j++) {
            if (r->r[j].country == si->country) {
                ri = &r->r[j];
                if (ri->rcount) {
                    // check for regions
                    size_t i1, j1;
                    for (i1 = 0; i1 < si->rcount; i1++) {
                        // look for the same region
                        for (j1 = 0; j1 < ri->rcount; j1++) {
                            const FSIdentifiedRegionItemRegion * rir, *sir;
                            sir = &si->regions[i1];
                            rir = &ri->regions[j1];
                            if (sir->region == rir->region) {
                                if (rir->srcount) {
                                    // check subregions
                                    size_t i2, j2;
                                    for (i2 = 0; i2 < sir->srcount; i2++) {
                                        // look for the same region
                                        for (j2 = 0; j2 < rir->srcount; j2++) {
                                            if (sir->subregions[i2] == rir->subregions[j2])
                                                break;
                                        }
                                        if (j2 == rir->srcount) {
                                            // subregion not found
                                            return false;
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        if (j1 == ri->rcount) {
                            // region not found
                            return false;
                        }
                    }
                }
                break;
            }
        }
        if (j == r->count) {
            // no country found
            return false;
        }
    }
    return true;
}
