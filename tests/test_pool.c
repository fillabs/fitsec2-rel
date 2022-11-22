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
#include "fitsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

const char * storage1 = "POOL_1";

int loadCertificates(FitSec * e, const pchar_t * _path);

int main(int argc, char** argv)
{
	FitSecConfig cfg;
	FitSec * e;

	FitSecConfig_InitDefault(&cfg);

	e = FitSec_New(&cfg, "1");

	if(argc > 1){
		for (int i = 1; i < argc; i++) {
			loadCertificates(e, argv[i]);
		}
	}else
		loadCertificates(e, storage1);

	FitSec_RelinkCertificates(e);

	FitSec_Clean(e, 1);
	FitSec_Free(e);
	return 0;
}
