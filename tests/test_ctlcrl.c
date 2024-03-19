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
#include "clog.h"
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

static time_t _curTime  = 0;
static char* _curStrTime = NULL;
static pchar_t* _storage = NULL;
static int _request = 0;

static char _o_u[1024];
static char* _o_u_path = NULL;
static char* _o_ctlSeries = NULL;

static copt_t options [] = {
    { "h?", "help",          COPT_HELP,     NULL,            "Print this help page"},
    { "C",  "config",        COPT_CFGFILE,  &cfgfile,        "Config file"         },
    { "t",  "time",          COPT_STR,      &_curStrTime,    "The ISO representation of starting time" },
    { "S",  "store",         COPT_PATH,     &_storage,       "Save received data in this location" },
    { "i",  "request",       COPT_BOOL,     &_request,       "Request CTL/CRL information if necessary" },
    { "D",  "dc",            COPT_STR,      &_o_u_path,      "Override all DC URLs" },

    { NULL, "ctlseries",     COPT_STR,      &_o_ctlSeries,   "IEEE SCMS CTL series ID (hex)"},

    { NULL, NULL, COPT_END, NULL, NULL }
};


static size_t _curl_receive(void const* buf, size_t eSize, size_t eCount, void* ptr) {
    if (eCount > 0) {
        int rc = FitSec_ApplyTrustInformation(ptr, _curTime ++ , buf, eSize + eCount);
        if(0 != rc){
			fprintf(stderr, "%s\n", FitSec_ErrorMessage(rc));
        }
    }
    return eCount;
}

static bool _process_http_request(FitSec* e, const char* url)
{
    bool ret = false;
    if(_o_u_path){
        const char * p = strstr(url, "/getcrl/");
        if(!p) p = strstr(url, "/getctl/");
        if(p){
            strcpy(_o_u_path, p);
            url = &_o_u[0];
        }
    }
    printf("Request: %s\n", url);

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
        curl_easy_setopt(req, CURLOPT_WRITEDATA, e);
        curl_easy_setopt(req, CURLOPT_TIMEOUT, 10);
        
        res = curl_easy_perform(req);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_operation() failed : %s\n", curl_easy_strerror(res));
        }
        else {
            long n;
            res = curl_easy_getinfo(req, CURLINFO_RESPONSE_CODE, &n);
            printf("ResponseCode: %ld\n", n);
            if(n < 300){
                ret = true;
            }
        }
    }
    curl_easy_cleanup(req);
    return ret;
}

static char * storage_path = NULL;
static char * storage_fn = NULL;
const char * _dt_exts[] = {
    "/",
    "/getcert/",
    "/getctl/",
    "/getcrl/",
    "/getlink/",
};

static bool _onEvent(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    if (event == FSEvent_HttpGetRequest) {
        return _process_http_request(e, params->httpGet.url);
    }else if (event == FSEvent_StoreData) {
        if(storage_path){
            char * b = storage_fn;
            b = cstrcpy(b, _dt_exts[params->store.type]);
            b = cstr_bin2hex(b, 16, (const char*)&params->store.id, 8);
            *b = 0;
            cstrnsave(params->store.data, params->store.len, storage_path);
        }
    }
    return true;
}

int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);

int main(int argc, char** argv)
{
    FitSec* e = NULL;

    clog_set_level(0, CLOG_DEBUG);
    
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
    if(_storage){
        storage_fn = cstrpdups(&storage_path, _storage, 32);
        cfg.storeTrustInformation = 1;
    }
    if(_o_u_path){
        _o_u_path = cstrcpy(_o_u, _o_u_path);
    }
    if(_o_ctlSeries){
        if( 16 != strlen(_o_ctlSeries) || 
            NULL == cstr_hex2bin((char*)&cfg.ctlSeriesId[0], 8, _o_ctlSeries, 16)
        ){
            fprintf(stderr, "CTL series ID shall contain 16 hexadecimal digits\n");
            return -1;
        }
    }
    
    e = FitSec_New(&cfg, "1");
    cfg.cbOnEvent = _onEvent;
    cfg.cbOnEventUser = e;

    for(int i=1; i<argc; i++){
        const char * p = argv[i];
        if (0 == strncmp("http://", p, 7) || 0 == strncmp("https://", p, 8)) {
            _process_http_request(e, p);
        }else{
            loadCertificates(e, _curTime, p);
        }
    }
    if(_request){
        if(_storage){
            cfg.storeTrustInformation = 1;
        }
        FitSec_RequestTrustInfo(e, _curTime+1, NULL);
    }
    FitSec_Free(e);
    FSMessageInfo_Cleanup(); 
    return 0;
}
