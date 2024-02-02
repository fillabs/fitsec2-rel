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
#include "fitsec.h"
#include "fitsec_error.h"
#include "fitsec_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#define sched_yield() SwitchToThread()
void usleep(__int64 usec);
#else
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#endif

static FitSecConfig cfg;

static pchar_t* cfgfile = NULL;

#define ITS_UTC_EPOCH 1072915200

static FS3DLocation position = { 514743600, 56248900, 0 };
static unsigned int _curTime = 0;
static unsigned int _beginTime = 0;
static unsigned int _msg_count = 100;
static float _rate = 10; // 10Hz

FILE * out;

char * outpath  = "msg.log";
char* storage1 = "POOL_1";
char* storage2 = "POOL_2_P2P";
char* storage3 = NULL;
char* _curStrTime = NULL;

        
static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "C",  "config",   COPT_CFGFILE,  &cfgfile,      "Config file"         },
    { "1",  "pool1",    COPT_STR,      &storage1,     "Storage directory 1"   },
    { "2",  "pool2",    COPT_STR,      &storage2,     "Storage directory 2"   },
    { "3",  "pool3",    COPT_STR,      &storage3,     "Storage directory 3"   },
    { "o",  "out",      COPT_STR,      &outpath,      "Output path" },
    { "n",  "count",    COPT_UINT,     &_msg_count,   "Message count" },
    { "r",  "rate",     COPT_FLOAT,    &_rate,        "Message rate in Hz" },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },


    { NULL, NULL, COPT_END, NULL, NULL }
};

static const char * _signer_types[] = {
    "self",
    "digest",
    "certificate",
    "none"
};
/*
static const unsigned long _leap_moments[] = {
    1136073600,
    1230768000,
    1341100800,
    1435708800,
};

static time_t addleapseconds(time_t t)
{
    int i;
    for (i = 0; i < sizeof(_leap_moments) / sizeof(_leap_moments[0]); i++){
        if (t < _leap_moments[i]) break;
    }
    return t + i;
}

static unsigned long unix2itstime32(time_t t)
{
    return ((unsigned long) addleapseconds(t)) - ITS_UTC_EPOCH;
}
*/
int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);
int strpdate(const char* s, struct tm* t);                // defined in utils.c


static char _defaultPayload[] = "1234567890";

static size_t SendMsg(FitSec* e, char* buf, size_t len, int stage, FSMessageInfo* m);
static size_t RecvMsg(FitSec* e, char* buf, size_t len, int stage, FSMessageInfo* m);

int main(int argc, char** argv)
{
    FitSec* e[3] = {NULL};

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

    if (outpath) {
        out = fopen(outpath, "w");
        if (out == NULL) {
            perror(outpath);
            return -1;
        }
    }
    else {
        out = stdout;
    }

    // setup crypto alg
    e[0] = FitSec_New(&cfg, "1");
    e[1] = FitSec_New(&cfg, "2");
    if( storage3 )
        e[2] = FitSec_New(&cfg, "3");

    if (0 >= loadCertificates(e[0], _curTime, storage1)) {
        return -1;
    }

    if (0 >= loadCertificates(e[1], _curTime, storage2)) {
        FitSec_Free(e[0]);
        return -1;
    }
//    FitSec_RelinkCertificates(e[0]);
//    FitSec_RelinkCertificates(e[1]);

    if (storage3){
        if (0 >= loadCertificates(e[2], _curTime, storage3)) {
            FitSec_Free(e[0]);
            FitSec_Free(e[1]);
            return -1;
        }
//        FitSec_RelinkCertificates(e[2]);
    }

    size_t len;
    char buf[1024];

    //	int opos = 0;
    FSMessageInfo ms = { 0 }, mr = { 0 };
    FSMessageInfo_SetBuffer(&ms, buf, sizeof(buf));

    _beginTime = _curTime;

    ms.sign.ssp.aid = FITSEC_AID_CAM;
    ms.sign.ssp.sspData.bits.version = 1;
    ms.position = position;
    ms.payloadType = FS_PAYLOAD_SIGNED;

    // skip first messages with certificate
    printf("Skip first messages with certificates\n");
    SendMsg(e[0], buf, sizeof(buf), 0, &ms);
    SendMsg(e[1], buf, sizeof(buf), 0, &ms);
    if(e[2]) SendMsg(e[2], buf, sizeof(buf), 0, &ms);

    // 1. send message with digest
    printf("\n1. Send CAM signed by Digest\n");
    ms.sign.ssp.sspData.opaque[0] = 1;
    ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(e[0], buf, sizeof(buf), 1, &ms);
    if (len > 0) {
        // 2. detect unknown digest
        RecvMsg(e[1], buf, len, 1, &mr);
        if(e[2]) RecvMsg(e[2], buf, len, 1, &mr);
    }

    // 2. send request for unknown certificate signed with certificate
    printf("\n2. Send CAM signed by unknown certificate with request for AT\n");
    ms.sign.ssp.sspData.opaque[0] = 1;
    ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(e[1], buf, sizeof(buf), 2, &ms);
    if (len > 0) {
        // detect request for certificate and new signed certificate, detect unknown AA certificate
        RecvMsg(e[0], buf, len, 2, &mr);
        if (e[2]) {
            RecvMsg(e[2], buf, len, 2, &mr);
        }
    }

    // 3. send request for unknown AA certificate
    printf("\n3. Send CAM signed by unknown cert with req for unknown AA\n");
    ms.sign.ssp.sspData.opaque[0] = 1;
    ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(e[0], buf, sizeof(buf), 3, &ms);
    if (len > 0) {
        // detect request for unknown certificate
        RecvMsg(e[1], buf, len, 3, &mr);
        if (e[2]) RecvMsg(e[2], buf, len, 3, &mr);
    }

    // 4. send AA certificate from 3rd party
    if (e[2]) {
        printf("\n4a. Send CAM signed by cert with request for AA from 3rd party\n");
        ms.sign.ssp.sspData.opaque[0] = 1;
        ms.sign.ssp.sspData.opaque[1] = 0;
        len = SendMsg(e[2], buf, sizeof(buf), 4, &ms);
        if (len > 0) {
            // validate message
            RecvMsg(e[0], buf, len, 4, &mr);
            RecvMsg(e[1], buf, len, 4, &mr);
        }

        printf("\n4b. Send CAM signed by digest with requested AA\n");
        ms.sign.ssp.sspData.opaque[0] = 1;
        ms.sign.ssp.sspData.opaque[1] = 0;
        len = SendMsg(e[2], buf, sizeof(buf), 4, &ms);
        if (len > 0) {
            // validate message
            RecvMsg(e[0], buf, len, 4, &mr);
            RecvMsg(e[1], buf, len, 4, &mr);
        }

        printf("\n4c. Send CAM signed by digest without requested AA \n");
        ms.sign.ssp.sspData.opaque[0] = 1;
        ms.sign.ssp.sspData.opaque[1] = 0;
        len = SendMsg(e[1], buf, sizeof(buf), 4, &ms);
        if (len > 0) {
            // validate message
            RecvMsg(e[0], buf, len, 4, &mr);
            RecvMsg(e[2], buf, len, 4, &mr);
        }

        // 5. send message containing requested AA certificate
        printf("\n5a. Send CAM signed by certificate without requested AA\n");
        ms.sign.ssp.sspData.opaque[0] = 1;
        ms.sign.ssp.sspData.opaque[1] = 0;
        len = SendMsg(e[0], buf, sizeof(buf), 5, &ms);
        if (len > 0) {
            // validate message
            RecvMsg(e[1], buf, len, 5, &mr);
            if (e[2]) RecvMsg(e[2], buf, len, 3, &mr);
        }
    }
    else {
        printf("\n4. Send CAM signed by digest with requested AA \n");
        ms.sign.ssp.sspData.opaque[0] = 1;
        ms.sign.ssp.sspData.opaque[1] = 0;
        len = SendMsg(e[1], buf, sizeof(buf), 4, &ms);
        if (len > 0) {
            // validate message
            RecvMsg(e[0], buf, len, 4, &mr);
        }
    }
    // 5. send message containing requested AA certificate
    printf("\n6. Send CAM signed by digest with requested AA\n");
    ms.sign.ssp.sspData.opaque[0] = 1;
    ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(e[0], buf, sizeof(buf), 6, &ms);
    if (len > 0) {
        // validate message
        RecvMsg(e[1], buf, len, 6, &mr);
        if (e[2]) RecvMsg(e[2], buf, len, 6, &mr);
    }

    printf("\n5. Send CAM signed by digest with requested AA\n");
    ms.sign.ssp.sspData.opaque[0] = 1;
    ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(e[1], buf, sizeof(buf), 6, &ms);
    if (len > 0) {
        // validate message
        RecvMsg(e[0], buf, len, 6, &mr);
        if (e[2]) RecvMsg(e[2], buf, len, 6, &mr);
    }
    if (e[2]) {
        printf("\n5. Send CAM signed by digest with requested AA\n");
        ms.sign.ssp.sspData.opaque[0] = 1;
        ms.sign.ssp.sspData.opaque[1] = 0;
        len = SendMsg(e[2], buf, sizeof(buf), 6, &ms);
        if (len > 0) {
            // validate message
            RecvMsg(e[0], buf, len, 6, &mr);
            RecvMsg(e[1], buf, len, 6, &mr);
        }
    }

    FitSec_Free(e[0]);
    FitSec_Free(e[1]);
    if (e[2]) FitSec_Free(e[2]);
    if(out != stdout){
        fclose(out);
    }
    return 0;
}


static size_t SendMsg(FitSec* e, char* buf, size_t bsize, int stage, FSMessageInfo* m)
{
    FSMessageInfo_SetBuffer(m, buf, bsize);
	m->sign.signerType = FS_SI_AUTO;    
    size_t len = FitSec_PrepareSignedMessage(e, m);
    if (len > 0) {
        m->payloadSize = sizeof(_defaultPayload);
        memcpy(m->payload, _defaultPayload, m->payloadSize);
        m->generationTime = (((FSTime64)_beginTime * 100) + stage) * 10000;
        
        if (FitSec_FinalizeSignedMessage(e, m)) {
            fprintf(stderr, "SEND %s %2d:\t OK %s\n", FitSec_Name(e), stage, _signer_types[m->sign.signerType]);
            return m->messageSize;
        }
    }
    fprintf(stderr, "SEND %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), stage, m->status, FitSec_ErrorMessage(m->status));
    return 0;


    return 0;
}

static size_t RecvMsg(FitSec* e, char* buf, size_t len, int stage, FSMessageInfo* m)
{
    m->generationTime = (((FSTime64)_beginTime * 100) + stage) * 10000;
    FSMessageInfo_SetBuffer(m, buf, len);
    size_t l = FitSec_ParseMessage(e, m);
    if (l && m->payloadType != FS_PAYLOAD_SIGNED) {
        m->status = FSERR_MESSAGE | FSERR_PAYLOAD | FSERR_TYPE | FSERR_INVALID;
        l = 0;
    }
    if (l == 0) {
        fprintf(stderr, "PARS %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), stage, m->status, FitSec_ErrorMessage(m->status));
        return 0;
    }
    if (!FitSec_ValidateSignedMessage(e, m)) {
        fprintf(stderr, "VALD %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), stage, m->status, FitSec_ErrorMessage(m->status));
        return 0;
    }
    fprintf(stderr, "RECV %s %2d:\t OK %s\n", FitSec_Name(e), stage, _signer_types[m->sign.signerType]);
    return m->messageSize;
}
