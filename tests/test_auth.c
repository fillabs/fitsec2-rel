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

#include "copts.h"
#include "cstr.h"
#include "cmem.h"
#include "../fitsec_pki.h"
#include "fitsec.h"
#include "fitsec_error.h"
#include "fitsec_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include <curl/curl.h>
#include <sys/stat.h>
#include <inttypes.h>

int strpdate(const char* s, struct tm* t);

static FitSecConfig cfg;

static pchar_t* cfgfile = NULL;

#define ITS_UTC_EPOCH 1072915200

//static FS3DLocation position = { 514743600, 56248900, 0 };

static uint8_t station_id [] = {
    0xb1, 0xb8, 0xc6, 0xe0, 0xb7, 0x5d, 0xd6, 0xf6,
    0x76, 0xd5, 0x77, 0x43, 0x6b, 0xb5, 0x41, 0xde
};

static FitSecPkiConfig pki_cfg = {
    {
        &station_id[0], sizeof(station_id),
        FS_NISTP256, NULL
    },
    DEFAULT_REQ_STORAGE_DURATION
};

static time_t _curTime  = 0;
static char* _curStrTime = NULL;
static const pchar_t * _canKeyPath = "canonical.nist256";
static const pchar_t * _stationIdPath = NULL;

static copt_t options [] = {
    { "h?", "help",          COPT_HELP,     NULL,            "Print this help page"},
    { "C",  "config",        COPT_CFGFILE,  &cfgfile,        "Config file"         },
    { "t",  "time",          COPT_STR,      &_curStrTime,    "The ISO representation of starting time" },
    { "K",  "canonical-key", COPT_PATH,     &_canKeyPath,    "Canonical private key path" },
    { "I",  "station-id",    COPT_PATH,     &_stationIdPath, "Station identifier path" },

    { NULL, NULL, COPT_END, NULL, NULL }
};


static size_t _curl_receive(void const* buf, size_t eSize, size_t eCount, void* ptr) {
    FitSecPki* pki = (FitSecPki*)ptr;
    if (eCount > 0) {
        FitSecPki_loadData(pki, buf, eSize * eCount);
    }
    return eCount;
}

static bool _process_http_request(FitSecPki* pki, const char* url, const char * body, size_t len)
{
    printf("Get: %s\n", url);
    //        return false;

    CURL* req = curl_easy_init();
    CURLcode res;
    if (req)
    {
        curl_easy_setopt(req, CURLOPT_URL, url);
        curl_easy_setopt(req, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(req, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(req, CURLOPT_WRITEFUNCTION, _curl_receive);
        curl_easy_setopt(req, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(req, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(req, CURLOPT_WRITEDATA, pki);
        curl_easy_setopt(req, CURLOPT_TIMEOUT, 10);
        if(body && len){
            curl_easy_setopt(req, CURLOPT_POST, 1L);
            curl_easy_setopt(req, CURLOPT_POSTFIELDSIZE, len);
            curl_easy_setopt(req, CURLOPT_POSTFIELDS, body);
        }
        
        res = curl_easy_perform(req);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_operation() failed : %s\n", curl_easy_strerror(res));
        }
        else {
            long n;
            res = curl_easy_getinfo(req, CURLINFO_RESPONSE_CODE, &n);
            printf("ResponseCode: %ld\n", n);
        }
    }
    curl_easy_cleanup(req);
    return true;
}


static bool _onEvent(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    FitSecPki * pki = user;
    assert(pki->e == e);
    if (event == FSEvent_HttpPostRequest) {
        return _process_http_request(pki, params->httpPost.url, params->httpPost.body, params->httpPost.bodylen);
    }
    return true;
}


int loadCertificates(FitSecPki * pki, const pchar_t * _path);

int main(int argc, char** argv)
{
    FitSec* e = NULL;

    FitSecConfig_InitDefault(&cfg);

    int flags = COPT_DEFAULT | COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP;
    argc = coptions(argc, argv, flags, options);
    if (COPT_ERC(argc)) {
        coptions_help(stdout, argv[0], 0, options, "Test");
        return -1;
    }

    if(_curStrTime){
        struct tm t;
        if(0 > strpdate(_curStrTime, &t)){
            fprintf(stderr, "%s: Unknown time format\n", _curStrTime);
            return -1;
        }
        _curTime = mkitstime32(&t);
    }else{
        _curTime = unix2itstime32(time(NULL));
    }
    
    e = FitSec_New(&cfg, "1");

    char *canKey, *end;
    end = cstraload(&canKey, _canKeyPath);
    if(end){
        const char * ext = cstrpathextension(_canKeyPath);
        pki_cfg.station.alg = FS_NISTP256;
        if(ext){
            if(strstr(ext, "nist")){
                if(strstr(ext, "384")){
                    pki_cfg.station.alg = FS_NISTP384;
                }
            }else if(strstr(ext, "bpool") || strstr(ext, "brainpool") || strstr(ext, "bp")){
                if(strstr(ext, "384")){
                    pki_cfg.station.alg = FS_BRAINPOOLP384R1;
                }else{
                    pki_cfg.station.alg = FS_BRAINPOOLP256R1;
                }
            }else if(strstr(ext, "sm2")){
                pki_cfg.station.alg = FS_SM2;
            }
        }
        pki_cfg.station.priv = (const uint8_t*)canKey;
    }

    FitSecPki * pki = FitSecPki_New(e, &pki_cfg);

    cfg.cbOnEvent = _onEvent;
    cfg.cbOnEventUser = e;

    CUNUSED const FSCertificate* last = NULL;
    char *buf  = callocate(65536);
    for(int i=1; i<argc; i++){
        struct stat st;
        int rc = stat(argv[i], &st);
        if(rc == 0){
            if (S_ISDIR(st.st_mode)) {
                loadCertificates(pki, argv[i]);
            }
            else if (S_ISREG(st.st_mode)) {
                char * end = cstrnload(buf, 65536, argv[i]);
                if (end) {
                    int error = 0;
                    if (((uint8_t)buf[0]) == 0x80) {
                        const FSCertificate * c = FitSec_InstallCertificate(e, buf, end - buf, NULL, 0, NULL, 0, &error);
                        if (c) {
                            last = c;
                            printf(" [%016"PRIX64"] - %s\n", cint64_hton(FitSec_CertificateDigest(c)), FitSec_ErrorMessage(error));
                        }
                    }
                    else {
                        error = FitSecPki_loadData(pki, buf, end - buf);
                        fprintf(stderr, "%s: %s\n", argv[i], FitSec_ErrorMessage(error));
                    }
                }
            }
        }
        else if (0 == cstrnstr("http://", 7, argv[i]) || 0 == cstrnstr("https://", 8, argv[i])) {
            _process_http_request(pki, argv[i], NULL, 0);
        }
	}

    FSMessageInfo m = {0};
    FSMessageInfo_SetBuffer(&m, buf, sizeof(buf));
    FSCertificateParams params_auth = {
        .vKeyAlg = FS_NISTP256,
        .eKeyAlg = -1,
        .appPermissions = {
            {FITSEC_AID_CRT_REQ,  1, {{ 0b11000000 }}},
            {0}
        }
    };

    if(FitSecPki_PrepareATRequest(pki, &params_auth, &m)){
        char * url;
        size_t ulen;
        if(FSCertificate_GetDC(m.encryption.cert, &url, &ulen)){
            if (cstrnequal("http", url, 4)) {
                _process_http_request(pki, url, m.message, m.messageSize);
            }
        }
    }

    FitSec_Free(e);
    FitSecPki_Free(pki);
    cfree(canKey);
    FSMessageInfo_Cleanup(); 
    return 0;
}
