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
#define _FILE_OFFSET_BITS 64

#include "cstr.h"
#include "cmem.h"
#include "fitsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#ifdef WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#endif

int loadCertificates(FitSec * e, const pchar_t * _path);

static char * _data;
static int    _dsize = 4096;
static FSHashedId8 _load_certificate(FitSec * e, pchar_t * path, pchar_t * fname)
{
	char *data, *end;
	char *vkey = NULL, *ekey = NULL;
	size_t   cert_len = 0, vkey_len = 0, ekey_len = 0;
	pchar_t *ext;
	FSHashedId8 digest = (FSHashedId8)-1;
	int error = 0;

	data = _data;
	end = cstrnload(data, _dsize, path);
	if (end > data){
		cert_len = end - data;

		printf("%-2s %-32.32s:", FitSec_Name(e), fname);
		
		// look for keys
		ext = cstrpathextension(fname);
		pchar_cpy(ext, ".vkey");
		vkey = end;
		end = cstrnload(vkey, _dsize - (vkey - data), path);
		if (end <= vkey){
			end = vkey; vkey = NULL;
		}
		else{
			vkey_len = end - vkey;
		}

		pchar_cpy(ext, ".ekey");
		ekey = end;
		end = cstrnload(ekey, _dsize - (ekey - data), path);
		if (end <= ekey){
			end = ekey; ekey = NULL;
		}
		else{
			ekey_len = end - ekey;
		}
		const FSCertificate* c =  FitSec_InstallCertificate(e, data, cert_len, vkey, vkey_len, ekey, ekey_len, &error);
        digest = FitSec_CertificateDigest(c);
        printf(" [%016"PRIX64"] - %s\n", cint64_hton(digest), FitSec_ErrorMessage(error));
	}
	else{
		error = -1;
		printf("%-2s: %s: Empty File\n", FitSec_Name(e), fname);
	}
	return digest;
}

int loadCertificates(FitSec * e, const pchar_t * _path)
{
	size_t plen;
	pchar_t *path;
	int ccount = 0;

	plen = _path ? pchar_len(_path) : 0;
	path = malloc((plen + 256) * sizeof(pchar_t));
	if (path == NULL) return -1;
	if (plen){
		memcpy(path, _path, plen * sizeof(pchar_t));
		while (plen && (path[plen - 1] == '/' || path[plen - 1] == '\\')) plen--;
	}
	if (plen == 0) path[plen++] = '.';
	path[plen] = 0;

	_data = malloc(_dsize); // it must not be more

#ifdef WIN32
	{
		WIN32_FIND_DATA fd;
		HANDLE h;

		fd.dwFileAttributes = GetFileAttributes(path);
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			pchar_cpy(path + plen, "/*.oer"); plen++;
			h = FindFirstFile(path, &fd);
			if (INVALID_HANDLE_VALUE != h) {
				do {
					if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
						pchar_cpy(path + plen, fd.cFileName);
						FSHashedId8 digest = _load_certificate(e, path, path + plen);
						if (digest != (FSHashedId8)-1) {
							ccount++;
						}
					}
				} while (FindNextFile(h, &fd));
				FindClose(h);
			}
		}
		else {
			FSHashedId8 digest = _load_certificate(e, path, path + plen);
			if (digest != (FSHashedId8)-1) {
				ccount++;
			}
		}
	}
#else
	{
		struct stat st;
		if(0 == stat(path, &st)){
			if (S_ISREG(st.st_mode)) {
				if (0 <= _load_certificate(e, path, path + plen)) {
					ccount++;
				}
			}else if (S_ISDIR(st.st_mode)) {
				DIR * d;
				struct dirent * de;
				d = opendir(path);
				if(d){
					path[plen++] = '/';
					while(NULL != (de = readdir(d))){
						pchar_t * ext = pchar_rchr(de->d_name, '.');
						if(ext && 0 == strcmp(ext, ".oer")){
							pchar_cpy(path + plen, de->d_name);
							if (0 <= _load_certificate(e, path, path + plen)){
								errno = 0;
								ccount++;
							}
						}
					}
					closedir(d);
				}
			}
			if (errno) {
				perror(path);
			}
		}
	}
#endif
	free(path);
	free(_data);
	return ccount;
}
