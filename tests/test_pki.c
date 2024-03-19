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
#include "fitsec_pki.h"
#include "fitsec.h"
#include "fitsec_error.h"
#include "fitsec_time.h"
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

static uint8_t _priv_key [48] = {
    0x32, 0xB0, 0xBA, 0xC1, 0x9C, 0x38, 0xE9, 0x3A,
    0x82, 0x14, 0x13, 0x28, 0x1C, 0x47, 0x55, 0xE6,
    0xDC, 0x25, 0xB6, 0xCE, 0x5A, 0x12, 0xDA, 0x8A, 
    0xAB, 0x49, 0xFC, 0x9B, 0xBC, 0x86, 0xED, 0xE2
};
static int _priv_key_fsize = 32;

static FitSecPkiConfig pki_cfg = {
    {
        &station_id[0], sizeof(station_id),
        FS_NISTP256, &_priv_key[0]
    },
    0, // no repetition
    DEFAULT_REQ_STORAGE_DURATION * 2
};

static time_t _curTime  = 0;
static char* _curStrTime = NULL;
static const pchar_t * _canKeyPath = NULL;
static const pchar_t * _stationIdPath = NULL;

static char _o_u[1024];
static char* _o_out = NULL;
static char* _o_u_path = NULL;
static const char* _o_dc = NULL;
static int _o_force = 0;
static int _o_verbose = 0;
static copt_t options [] = {
    { "h?", "help",          COPT_HELP,     NULL,            "Print this help page"},
    { "v",  "verbose",       COPT_BOOL,     &_o_verbose,     "be verbose"},
    { "C",  "config",        COPT_CFGFILE,  &cfgfile,        "Config file"         },
    { "t",  "time",          COPT_STR,      &_curStrTime,    "The ISO representation of starting time" },
    { "K",  "canonical-key", COPT_PATH,     &_canKeyPath,    "Canonical private key path" },
    { "I",  "station-id",    COPT_PATH,     &_stationIdPath, "Station identifier path" },

    { "O",  "override",      COPT_STR,      &_o_u_path,      "Override hosts of all DC URLs" },
    { "f",  "force",         COPT_BOOL,     &_o_force,       "force all operations" },

    { "o",  "out",           COPT_PATH,     &_o_out,         "Path to store certificates" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

static size_t _curl_receive(void const* buf, size_t eSize, size_t eCount, void* ptr) {
    FitSecPki* pki = (FitSecPki*)ptr;
    if (eCount > 0) {
        FSMessageInfo m = { 0 };
        m.generationTime =FSTime64from32(_curTime);
        m.message = (char*)buf;
        m.messageSize = eSize * eCount;
        size_t len = FitSec_ParseMessage(pki->e, &m);
        if (len <= 0 || !FitSecPki_loadMessage(pki, &m)) {
            fprintf(stderr, "PKI: %s\n", FitSec_ErrorMessage(m.status));
        }
    }
    return eCount;
}

static bool _process_http_request(FitSecPki* pki, const char* url, const char * body, size_t len)
{
    printf("Request: %s\n", url);

    if(_o_u_path && (&_o_u[0] != url)){
        const char * p;
        if(!(p = strstr(url, "/getcrl/"))){ 
            if(!(p = strstr(url, "/getctl/"))){
                if(!(p = strchr(url, '/'))){
                    if(!p) p = "";
        }}}
        strcpy(_o_u_path, p);
        url = &_o_u[0];
    }

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
            struct curl_slist *hs=NULL;
            hs = curl_slist_append(hs, "Content-Type: application/x-its-request");
            curl_easy_setopt(req, CURLOPT_HTTPHEADER, hs);
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

static const char * _CERT_STATE_NAME[] = {
    "UNKNOWN",
    "TRUSTED",
    "INVALID",
    "ERROR"
};

static bool _onEvent(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    if (event == FSEvent_HttpGetRequest) {
        FitSecPki * pki = user;
        assert(pki->e == e);
        return _process_http_request(pki, params->httpGet.url, NULL, 0);
    }

    if (event == FSEvent_HttpPostRequest) {
        FitSecPki * pki = user;
        assert(pki->e == e);
        return _process_http_request(pki, params->httpPost.url, params->httpPost.body, params->httpPost.bodylen);
    }

    if(event == FSEvent_CertStatus){
        FSHashedId8 digest = FSCertificate_Digest(params->certStateChange.certificate);
        fprintf(stderr, "["cPrefixUint64"X]: %s=>%s\n", cint64_hton(digest), 
                                                       _CERT_STATE_NAME[params->certStateChange.from&3],_CERT_STATE_NAME[params->certStateChange.to&3]);
        
        if(_o_out){
            const char * dir = "";
            if(params->certStateChange.to == FSCERT_INVALID){
                dir = "invalid/";
            }
            size_t len;
            const char * d = FSCertificate_Buffer(params->certStateChange.certificate, &len);
            if(d){
                char * end = cstrend(_o_out);
                sprintf(end, "/%s"cPrefixUint64"X.oer", dir,cint64_hton(digest));
                if (cstrnsave(d, len, _o_out)){
                    fprintf(stderr, "["cPrefixUint64"X]: stored as %s [%ld bytes]\n", cint64_hton(digest), _o_out, len);
                }else{
                    fprintf(stderr, "["cPrefixUint64"X]: failed to store as %s\n", cint64_hton(digest), _o_out);
                }
                pchar_t * ext = cstrpathextension(_o_out);
                FSCrypt * ce = FSCrypt_FindEngine(FitSec_GetConfig(e)->signEngine);
                if(ce){
                    const FSPrivateKey * k = FSCertificate_GetVerificationPrivateKey(params->certStateChange.certificate);
                    if(k){
                        uint8_t buf[256];
                        size_t len = FSKey_ExportPrivate(ce, k, buf);
                        if(len){
                            strcpy(ext, ".vkey");
                            cstrnsave((const char*)buf, len, _o_out);
                        }
                    }
                }
                ce = FSCrypt_FindEngine(FitSec_GetConfig(e)->encryptEngine);
                if(ce){
                    const FSPrivateKey * k = FSCertificate_GetEncryptionPrivateKey(params->certStateChange.certificate);
                    if(k){
                        uint8_t buf[256];
                        size_t len = FSKey_ExportPrivate(ce, k, buf);
                        if(len){
                            strcpy(ext, ".ekey");
                            cstrnsave((const char*)buf, len, _o_out);
                        }
                    }
                }
                *end = 0;
            }
        }
        if(_o_dc){
            if(params->certStateChange.to == FSCERT_TRUSTED){
                FSCertificate_SetDC(params->certStateChange.certificate, _o_dc, 0);
            }
        }

        return true;
    }
    
    if(event == FSEvent_StoreData){
        if(_o_out){
            if(params->store.type == FSDT_CERTIFICATE){
                char * e = cstrend(_o_out);
                sprintf(e, "/"cPrefixUint64"X.oer", cint64_hton(params->store.id));
                if (cstrnsave(params->store.data, params->store.len, _o_out)){
                    fprintf(stderr, "["cPrefixUint64"X]: stored as %s\n", cint64_hton(params->store.id), _o_out);
                }else{
                    fprintf(stderr, "["cPrefixUint64"X]: failed to store as %s\n", cint64_hton(params->store.id), _o_out);
                }
                *e = 0;
            }
        }
    }

    return true;
}

int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);

int main(int argc, char** argv)
{
    FitSec* e = NULL;

    FitSecConfig_InitDefault(&cfg);

    int flags = COPT_DEFAULT | COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP;
    argc = coptions(argc, argv, flags, options);
    if (COPT_ERC(argc)) {
        coptions_help(stdout, argv[0], 0, options, "commands, certificates or CRL/CTL files or HTTP(S) URLs\n"
            "Commands:\n"
            "  dc <url>   - set DC URL for following operations\n"
            "  enrol[:EA] - Run enrolment procedure\n"
            "  auth[:AA]  - Run authorization procedure\n"
            "  req        - Update CRL/CTL for all installed Root CA certs\n"
            "  <path>     - load certificates or trust information from path (recursively)\n"
            "  <URL>      - load trust information from given URL"
        );
        return -1;
    }

    if(_o_u_path){
        strncpy(_o_u, _o_u_path, sizeof(_o_u));
        _o_u_path = cstrend(_o_u);
    }

    if(_o_verbose){
        clog_set_level(0, CLOG_DEBUG);
    }

    if(_o_out){
        _o_out = cstrdups(_o_out, 32);
        cfg.storeTrustInformation = 1;
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

    if(_canKeyPath){
        const char * ext = cstrpathextension(_canKeyPath);
        if(ext){
            if(cstrequal(ext, "nist384")){
                _priv_key_fsize = 48; pki_cfg.station.alg = FS_NISTP384;
            } else if(cstrequal(ext, "bpool384")){
                _priv_key_fsize = 48; pki_cfg.station.alg = FS_BRAINPOOLP384R1;
            } else if(cstrequal(ext, "bpool256")){
                pki_cfg.station.alg = FS_BRAINPOOLP256R1;
            } else if(cstrequal(ext, "sm2")){
                pki_cfg.station.alg = FS_SM2;
            }
        }
        uint8_t * e = (uint8_t *)cstrnload((char*)&_priv_key[0], sizeof(_priv_key), _canKeyPath);
        if(e - &_priv_key[0] != _priv_key_fsize){
            if(errno) perror(_canKeyPath);
            else      fprintf(stderr, "%s: private key file size mismatch\n", _canKeyPath);
            return -1;
        }
    }
    
    if(_stationIdPath){
        uint8_t * e = (uint8_t *)cstrnload((char*)&station_id[0], sizeof(station_id), _stationIdPath);
        if(e - &station_id[0] != 16){
            if(errno) perror(_canKeyPath);
            else      fprintf(stderr, "%s: station id file size mismatch\n", _stationIdPath);
            return -1;
        }
    }
   
    e = FitSec_New(&cfg, "1");

    FitSecPki * pki = FitSecPki_New(e, &pki_cfg);

    cfg.cbOnEvent = _onEvent;
    cfg.cbOnEventUser = e;

    char *buf  = callocate(65536);
    FSMessageInfo m = {
        .generationTime = ((uint64_t)_curTime) * 1000000
    };
    FSMessageInfo_SetBuffer(&m, buf, 65536);
    FSCertificateParams ec_params = {
        .vKeyAlg = FS_NISTP256,
        .eKeyAlg = -1,
        .startTime = _curTime,
        .duration = 168,
        .durationType = dt_hours,
        .appPermissions = {
//            {FITSEC_AID_CAM,      3, {.bits={1}}},
//            {FITSEC_AID_DENM,     4, {.bits={1}}},
            {FITSEC_AID_CRT_REQ,  2, {.bits={0x01, {0xC0}}}},
            {0}
        }
    };

    FSCertificateParams at_params = {
        .vKeyAlg = FS_NISTP256,
        .eKeyAlg = -1,
        .startTime = _curTime,
        .duration = 20,
        .durationType = dt_hours,
        .appPermissions = {
            {FITSEC_AID_CAM,      3, {.bits={1}}},
            {FITSEC_AID_DENM,     4, {.bits={1}}},
            {0}
        }
    };

    int force = _o_force;
    for(int i=1; i<argc; i++){
        if(cstrequal("dc", argv[i])){
            i++;
            if(i == argc || (memcmp("http://", argv[i], 7) && memcmp("https://", argv[i], 8))) {
                fprintf(stderr, "HTTP(S) URL shall be specified for DC\n");
            }
            _o_dc = argv[i];
        }else if(cstrequal("force", argv[i])){
            force = 1;
        }else if(cstrequal("req", argv[i])){
            FitSec_RequestTrustInfo(e, (force ? 0 : _curTime), pki);
            force = _o_force;
        }else{
            size_t rc = 0;
            if(cstrnequal("enrol", argv[i], 5)){
                const char * ea = argv[i]+5;
                ec_params.ca.name = (*ea == ':') ? ea + 1 : NULL;
                rc = FitSecPki_PrepareECRequest(pki, &ec_params, &m);
                if(rc == 0){
                    fprintf(stderr, "Enrollment error: %s\n", FitSec_ErrorMessage(m.status));
                    continue;
                }
            }else if(cstrnequal("auth", argv[i], 4)){
                const char * ca = argv[i]+4;
                ec_params.ca.name = (*ca == ':') ? ca + 1 : NULL;
                rc = FitSecPki_PrepareATRequest(pki, &at_params, &m);
                if(rc == 0){
                    fprintf(stderr, "Authorization error: %s\n", FitSec_ErrorMessage(m.status));
                    continue;
                }
            }
            if(rc){
                const char * url;
                size_t ulen;
                if(!FSCertificate_GetDC(m.encryption.cert, (char**)&url, &ulen)){
                    fprintf(stderr, "Enrollment error: %s\n", FitSec_ErrorMessage(m.status));
                    continue;
                }
                if (cstrnequal("http", url, 4)) {
                    _process_http_request(pki, url, m.message, m.messageSize);
                }
            }else if (0==memcmp("http://", argv[i], 7) || 0==memcmp("https://", argv[i], 8)) {
                _process_http_request(pki, argv[i], NULL, 0);
            }else{
                loadCertificates(e, _curTime, argv[i]);
            }
        }
	}

    free(buf);
    FitSec_Free(e);
    FitSecPki_Free(pki);
    FSMessageInfo_Cleanup(); 
    return 0;
}
