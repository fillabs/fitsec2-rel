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
#include "fitsec_pki.h"
#include "fitsec_error.h"
#include "fitsec_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "C",  "config",   COPT_CFGFILE,  &cfgfile,      "Config file"         },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },

    { NULL, NULL, COPT_END, NULL, NULL }
};


static size_t _curl_receive(void const* buf, size_t eSize, size_t eCount, void* ptr) {
    FitSec* e = (FitSec*)ptr;
    if (eCount > 0) {
        FitSecPki_loadData(e, buf, eSize * eCount);
    }
    return eCount;
}

static bool _process_http_request(FitSec* e, const char* url)
{
    printf("Request: %s\n", url);
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
        curl_easy_setopt(req, CURLOPT_WRITEDATA, e);
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
    if (event == FSEvent_HttpGetRequest) {
        return _process_http_request(e, params->httpReq.url);
    }
    return true;
}


int loadCertificates(FitSec * e, const pchar_t * _path);

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

    cfg.cbOnEvent = _onEvent;
    cfg.cbOnEventUser = e;

    char * buf  = callocate(65536);
    CUNUSED const FSCertificate* last = NULL;
    for(int i=1; i<argc; i++){
        struct stat st;
        int rc = stat(argv[i], &st);
        if(rc == 0){
            if (st.st_mode & S_IFDIR) {
                loadCertificates(e, argv[i]);
            }
            else if (st.st_mode & S_IFREG) {
                char* end = cstrnload(buf, 65536, argv[i]);
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
                        error = FitSecPki_loadData(e, buf, end - buf);
                        fprintf(stderr, "%s: %s\n", argv[i], FitSec_ErrorMessage(error));
                    }
                }
            }
        }
        else if (0 == cstrnstr("http://", 7, argv[i]) || 0 == cstrnstr("https://", 8, argv[i])) {
            _process_http_request(e, argv[i]);
        }
	}
    free(buf);

    FitSecPki_requestCRL(e, NULL);
    FitSecPki_requestCTL(e, NULL);

    FitSec_Free(e);
    FSMessageInfo_Cleanup(); 
    return 0;
}
