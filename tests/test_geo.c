/*********************************************************************
This file is a part of FItsSec project: Implementation of ETSI TS 103 097
Copyright (C) 2015  Denis Filatov (danya.filatov()gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed under GNU GPLv3 in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar.  If not, see <http://www.gnu.org/licenses/gpl-3.0.txt>.
@license GPL-3.0+ <http://www.gnu.org/licenses/gpl-3.0.txt>

In particular cases this program can be distributed under other license
by simple request to the author. 
*********************************************************************/
#define _CRT_SECURE_NO_WARNINGS

#include "cstr.h"
#include "fitsec_geometry.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define BASE_LAT 436169099
#define BASE_LON  70533404
#define LAT_IN_METTER 90
#define LON_IN_METTER 123


#define DO_TEST(NAME, RES, TEST) do {\
	bool _ret_ = ((RES) == (TEST)); \
    printf("%-60.60s: %s\x1b[0m\n", NAME, _ret_ ? "\x1b[32mPASS" : "\x1b[31mERROR"); \
}while(0);


int main(int argc, char** argv)
{
	// check Circular
	FSGeoRegion* c, * r, *cs, *p;
	c = FSGeo_New_Curcular(BASE_LAT, BASE_LON, 1000);
	// check the center is in the region
	DO_TEST("Circular contains center", true, FSGeo_IsLocationInside(c, BASE_LAT, BASE_LON));
	DO_TEST("Circular contains point inside", true, FSGeo_IsLocationInside(c, BASE_LAT + 100, BASE_LON + 100));
	DO_TEST("Circular NOT contain point outside", false, FSGeo_IsLocationInside(c, BASE_LAT + (LAT_IN_METTER * 1200), BASE_LON + (LON_IN_METTER * 1200)));

	r = FSGeo_New_Rectangular();
	FSGeo_Rectangular_Add(r,
		BASE_LAT + 500 * LAT_IN_METTER,
		BASE_LON - 500 * LON_IN_METTER,
		BASE_LAT - 500 * LAT_IN_METTER,
		BASE_LON + 500 * LON_IN_METTER
		);
	DO_TEST("Rectangular 1 contains point inside", true, FSGeo_IsLocationInside(r, BASE_LAT + 100, BASE_LON + 100));
	DO_TEST("Rectangular 1 contains point outside", false, FSGeo_IsLocationInside(r, BASE_LAT + (LAT_IN_METTER * 600), BASE_LON + (LON_IN_METTER * 600)));
	DO_TEST("Rectangular 1 contains the top-left point", true, FSGeo_IsLocationInside(r, BASE_LAT + (LAT_IN_METTER * 500), BASE_LON - (LON_IN_METTER * 500)));
	DO_TEST("Rectangular 1 contains the bottom-right point", true, FSGeo_IsLocationInside(r, BASE_LAT - (LAT_IN_METTER * 500), BASE_LON + (LON_IN_METTER * 500)));

	DO_TEST("Big Circle contains rectangular",   true, FSGeo_IsRegionInside(c, r));
	DO_TEST("Rectangle contains BIG circle", false, FSGeo_IsRegionInside(r, c));


	FSGeo_Rectangular_Add(r,
		BASE_LAT + 500  * LAT_IN_METTER,
		BASE_LON + LON_IN_METTER * 1000,
		BASE_LAT - 500  * LAT_IN_METTER,
		BASE_LON + LON_IN_METTER * 2000
	);

	DO_TEST("Rectangular 2 contains point inside", true, FSGeo_IsLocationInside(r, BASE_LAT + 100, BASE_LON + (LON_IN_METTER * 1800)));
	DO_TEST("Rectangular 2 contains point outside on the left", false, FSGeo_IsLocationInside(r, BASE_LAT + (LAT_IN_METTER * 400), BASE_LON + (LON_IN_METTER * 800)));
	DO_TEST("Rectangular 2 contains point outside on the right", false, FSGeo_IsLocationInside(r, BASE_LAT + (LAT_IN_METTER * 400), BASE_LON + (LON_IN_METTER * 2500)));
	DO_TEST("Rectangular 2 contains the top-left point", true, FSGeo_IsLocationInside(r, BASE_LAT + (LAT_IN_METTER * 500), BASE_LON + (LON_IN_METTER * 1000)));
	DO_TEST("Rectangular 2 contains the bottom-right point", true, FSGeo_IsLocationInside(r, BASE_LAT - (LAT_IN_METTER * 500), BASE_LON + (LON_IN_METTER * 2000)));

	for (int i = 2; i < 8; i++) {
		FSGeo_Rectangular_Add(r,
			BASE_LAT + LAT_IN_METTER * 500,
			BASE_LON + LON_IN_METTER * (i * 1500 - 500),
			BASE_LAT - LAT_IN_METTER * 500,
			BASE_LON + LON_IN_METTER * (i * 1500 + 500)
		);
	}

	for (int i = 7; i < 8; i++) {
		char s[60];
		sprintf(s, "Rectangular %d contains point inside", i);
		DO_TEST(s, true, FSGeo_IsLocationInside(r, BASE_LAT, BASE_LON + LON_IN_METTER * (i * 1500 + 400)));
		
		sprintf(s, "Rectangular %d contains point outside", i);
		DO_TEST(s, false, FSGeo_IsLocationInside(r, BASE_LAT, BASE_LON + LON_IN_METTER * (i * 1500 + 700)));
	}

	DO_TEST("Big Circle contains rectangular", false, FSGeo_IsRegionInside(c, r));

	cs = FSGeo_New_Curcular(BASE_LAT + LAT_IN_METTER * 300, BASE_LON + LON_IN_METTER * (7 * 1500 + 300), 100);
	DO_TEST("Rectangular contains small circle", true, FSGeo_IsRegionInside(r, cs));

	static const int32_t _points[] = {
		BASE_LAT + LAT_IN_METTER * 400, BASE_LON - LON_IN_METTER * 400,
		BASE_LAT + LAT_IN_METTER * 400, BASE_LON + LON_IN_METTER * 400,
		BASE_LAT - LAT_IN_METTER * 400, BASE_LON + LON_IN_METTER * 400,
		BASE_LAT - LAT_IN_METTER * 400, BASE_LON - LON_IN_METTER * 400
	};
	p = FSGeo_New_Polygonal(4, _points);

	DO_TEST("Rectangular contains polygon", true, FSGeo_IsRegionInside(r, p));
	DO_TEST("Polygon contains rectangular", false, FSGeo_IsRegionInside(p, r));
	DO_TEST("Polygon contains small circular", true, FSGeo_IsRegionInside(p, cs));
	DO_TEST("Polygon contains big circular", false, FSGeo_IsRegionInside(p, c));
}
