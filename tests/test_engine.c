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
#include "fitsec_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

static FitSecConfig cfg1, cfg2;

static pchar_t* cfgfile = NULL;

static FS3DLocation position = { 514743600, 56248900, 0 };
static unsigned int _curTime = 0;
static unsigned int _beginTime = 0;

FILE * out;

char * outpath  = "msg.log";
char * storage1 = "POOL_1";
char * storage2 = "POOL_2";
char* _curStrTime = NULL;

static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "C",  "config",   COPT_CFGFILE,  &cfgfile,      "Config file"         },
    { "1",  "pool1",    COPT_STR,      &storage1,     "Storage directory 1"   },
    { "2",  "pool2",    COPT_STR,      &storage2,     "Storage directory 2"   },
    { "o", "out",       COPT_STR,      &outpath,      "Output path" },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

static const char * _signer_types[] = {
    "self",
    "digest",
    "certificate",
    "chain",
    "other",
};

static int SendMsg(const char * tn, FitSec * e, char * buf, FSMessageInfo * info);
static int RecvMsg(const char * tn, FitSec * e, char * buf, int len, FSMessageInfo * info);

static void print_x(FILE * f, const char * const ptr, int len);

int strpdate(const char* s, struct tm* t);                // defined in utils.c
int loadCertificates(FitSec * e, const pchar_t * _path);

static void test_CAM(FitSec * e1, FitSec* e2);
static void test_DENM(FitSec * e1, FitSec* e2);
static void test_CAM_P2P(FitSec * e1, FitSec* e2);
static void test_CAM_SSP(FitSec * e1, FitSec * e2);

static bool _onEvent(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    return true;
}

static char _defaultPayload[] = "1234567890";

int main(int argc, char** argv)
{
    FitSec * e1, *e2;

    FitSecConfig_InitDefault(&cfg1);
    FitSecConfig_InitDefault(&cfg2);

    int flags = COPT_DEFAULT | COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP;
    argc = coptions(argc, argv, flags, options);
    if (COPT_ERC(argc)) {
        coptions_help(stdout, argv[0], 0, options, "Test");
        return -1;
    }

    _curTime = unix2itstime32(1572298186);

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
//    cfg1.crypt = FSCryptEngineConfig_Default();
//    cfg2.crypt = FSCryptEngineConfig_Default();

    e1 = FitSec_New(&cfg1, "1");
    e2 = FitSec_New(&cfg2, "2");

    cfg1.cbOnEvent = cfg2.cbOnEvent = _onEvent;
    cfg1.cbOnEventUser = e2;
    cfg2.cbOnEventUser = e1;

    if (0 >= loadCertificates(e1, storage1)) {
        return -1;
    }
    
    if (0 >= loadCertificates(e2, storage2)) {
        FitSec_Free(e1);
        return -1;
    }
    FitSec_RelinkCertificates(e1);
    FitSec_RelinkCertificates(e2);

	test_CAM(e1, e2);

//	test_DENM(e1, e2);

//    test_CAM_P2P(e1, e2);

//    FitSec_Free(e1);
//    FitSec_Free(e2);

    return 0;
}
/*
#ifdef __GNUC__
#define __FUNCTION__ __func__
#endif
*/
static void test_CAM(FitSec * e1, FitSec * e2) {

    char buf[1024];
    int i;
    //int opos = 0;

    FSMessageInfo ms = { 0 };
    FSMessageInfo_SetBuffer(&ms, buf, sizeof(buf));

    ms.position = position;
    ms.sign.ssp.aid = FITSEC_AID_CAM;
    ms.sign.ssp.sspData.bits.version = 1;
    ms.payloadType = FS_PAYLOAD_SIGNED;

    _beginTime = _curTime;

    // test 1: Send 20 CAM and read it

    ms.generationTime = ((FSTime64)_beginTime) * 1000;

    for (i = 0; i < 100; i++) {
        ms.generationTime += 100000; // +100 msec
        size_t len = FitSec_PrepareSignedMessage(e1, &ms);
        ms.payloadSize = sizeof(_defaultPayload);
        memcpy(ms.payload, _defaultPayload, ms.payloadSize);
        len = FitSec_FinalizeSignedMessage(e1, &ms);
        if(len <=0){
            fprintf(stderr, "SEND %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e1), __FUNCTION__, ms.status, FitSec_ErrorMessage(ms.status));
        }
        else {
            fprintf(stderr, "SEND %s %s:\t OK %s\n", FitSec_Name(e1), __FUNCTION__, _signer_types[ms.sign.signerType]);

            FSMessageInfo mr = { 0 };
            if (!FitSec_ParseSignedMessage(e2, &mr, buf, len)) {
                fprintf(stderr, "PARS %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e2), __FUNCTION__, mr.status, FitSec_ErrorMessage(mr.status));
            }
            else {
                if (!FitSec_ValidateSignedMessage(e2, &mr)) {
                    fprintf(stderr, "VALD %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e2), __FUNCTION__, mr.status, FitSec_ErrorMessage(mr.status));
                }
            }
        }
    }
}

    // test 2: Send 10 DENM and read it
static void test_DENM(FitSec * e1, FitSec * e2) {

    char buf[1024];
    int i, len;
//	int opos = 0;
    FSMessageInfo ms = { 0 }, mr = { 0 };
    FSMessageInfo_SetBuffer(&ms, buf, sizeof(buf));
    FSMessageInfo_SetBuffer(&mr, buf, sizeof(buf));

    _beginTime = _curTime;

    ms.sign.ssp.aid = 37;
    ms.sign.ssp.sspData.bits.version = 1;
    ms.position = position;
    ms.payloadType = FS_PAYLOAD_SIGNED;
    ms.generationTime = ((FSTime64)_beginTime) * 1000;

    for (i = 0; i < 20; i++) {
        ms.generationTime += 300000;
        len = SendMsg(__FUNCTION__, e1, buf, &ms);
        if (len > 0) {
            //			printf("OUT POS = %04X\n", opos); opos += len;
            print_x(out, buf, len);
            RecvMsg(__FUNCTION__, e2, buf, len, &mr);
        }
    }
}

static void test_CAM_P2P(FitSec * e1, FitSec * e2) {

    char buf[1024];
    int len;
//	int opos = 0;
    FSMessageInfo ms = { 0 }, mr = { 0 };
    FSMessageInfo_SetBuffer(&ms, buf, sizeof(buf));
    FSMessageInfo_SetBuffer(&mr, buf, sizeof(buf));

    _beginTime = _curTime;
    
    FitSec_Clean(e1, false);
    FitSec_Clean(e2, false);
    
    ms.sign.ssp.aid = 36;
    ms.position = position;
    ms.sign.ssp.sspData.bits.version = 1;
    ms.payloadType = FS_PAYLOAD_SIGNED;
    ms.generationTime = ((FSTime64)_beginTime) * 1000;

    // skip first messages with certificate
    printf("Skip first messages with certificates\n");
    len = SendMsg(__FUNCTION__, e1, buf, &ms);
    //	len = SendMsg(testName, e2, buf, &ms);
    //	printf("OUT POS = %04X\n", opos); opos += len;
    print_x(out, buf, len);
    len = SendMsg(__FUNCTION__, e2, buf, &ms);
    //	len = SendMsg(testName, e2, buf, &ms);
    //	printf("OUT POS = %04X\n", opos); opos += len;
    print_x(out, buf, len);

    // 1. send message with digest
    printf("\nSend CAM signed by Digest\n");
    ms.sign.ssp.sspData.opaque[0] = 1; ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(__FUNCTION__, e1, buf, &ms);
    if (len > 0) {
        //		printf("OUT POS = %04X\n", opos); opos += len;
        print_x(out, buf, len);
        // 2. detect unknown digest
        RecvMsg(__FUNCTION__, e2, buf, len, &mr);
    }

    // 2. send request for unknown certificate signed with certificate
    printf("\nSend CAM signed by unknown certificate with request for AT\n");
    ms.sign.ssp.sspData.opaque[0] = 1; ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(__FUNCTION__, e2, buf, &ms);
    if (len > 0) {
        //		printf("OUT POS = %04X\n", opos); opos += len;
        print_x(out, buf, len);
        // 1. detect request for certificate and new signed certificate
        //    detect unknown AA certificate
        RecvMsg(__FUNCTION__, e1, buf, len, &mr);
    }

    // 3. send request for unknown AA certificate
    printf("\nSend CAM signed by unknown cert with req for unknown AA\n");
    ms.sign.ssp.sspData.opaque[0] = 1; ms.sign.ssp.sspData.opaque[1] = 0;
    len = SendMsg(__FUNCTION__, e1, buf, &ms);
    if (len > 0) {
        //		printf("OUT POS = %04X\n", opos); opos += len;
            print_x(out, buf, len);
        // 2. detect request for unknown certificate
        RecvMsg(__FUNCTION__, e2, buf, len, &mr);
    }

    // 4. send AA certificate
    printf("\nSend CAM signed by digest with requested AA\n");
    ms.sign.ssp.sspData.opaque[0] = 1; ms.ssp.sspData.opaque[1] = 0;
    len = SendMsg(__FUNCTION__, e2, buf, &ms);
    if (len > 0) {
        //		printf("OUT POS = %04X\n", opos); opos += len;
        print_x(out, buf, len);
        // 1. validate message
        RecvMsg(__FUNCTION__, e1, buf, len, &mr);
    }
    // 5. send message containing requested AA certificate
    printf("\nSend CAM signed by digest with requested AA\n");
    ms.ssp.sspData.opaque[0] = 1; ms.ssp.sspData.opaque[1] = 0;
    len = SendMsg(__FUNCTION__, e1, buf, &ms);
    if (len > 0) {
        //		printf("OUT POS = %04X\n", opos); opos += len;
        print_x(out, buf, len);
        // 2. validate message
        RecvMsg(__FUNCTION__, e2, buf, len, &mr);
    }
}

static void test_CAM_SSP(FitSec * e1, FitSec * e2) {

    char buf[1024];
    int len;
    //	int opos = 0;
    FSMessageInfo ms = { 0 }, mr = { 0 };

    ms.ssp.aid = 36;
    ms.ssp.sspData.bits.version = 1;
    ms.ssp.sspData.bits.flags[0] = 0xFF;
    ms.position = position;
    ms.payloadType = FS_PAYLOAD_SIGNED;
    ms.generationTime = ((FSTime64)_beginTime) * 1000;

    ms.generationTime += 300000;
    len = SendMsg(__FUNCTION__, e1, buf, &ms);
    if (len > 0) {
        //			printf("OUT POS = %04X\n", opos); opos += len;
        print_x(out, buf, len);
        RecvMsg(__FUNCTION__, e2, buf, len, &mr);
    }
}



static int SendMsg(const char * tn, FitSec * e, char * buf, FSMessageInfo * info)
{
    int ret;
    info->payload = "0123456789";
    info->payloadSize = 10;
    ret = (int) FitSec_SignedMessage(e, info, buf, 1024);
    if (ret < 0){
        fprintf(stderr, "SEND %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), tn, info->status, FitSec_ErrorMessage(info->status));
    }
    else{
        fprintf(stderr, "SEND %s %s:\t OK %s\n", FitSec_Name(e), tn, _signer_types[info->signerType]);
    }
    return ret;
}

static int RecvMsg(const char * tn, FitSec * e, char * buf, int len, FSMessageInfo * info)
{
    bool ret = FitSec_VerifySignedMessage(e, info, buf, len);
    if (!ret){
        fprintf(stderr, "RECV %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), tn, info->status, FitSec_ErrorMessage(info->status));
    }
    else{
#ifdef _MSC_VER
        fprintf(stderr, "RECV %s %s:\t %u ", FitSec_Name(e), tn, (unsigned int)(info->generationTime / 1000 - _beginTime));
        fprintf(stderr, _signer_types[info->signerType]);
        fprintf(stderr, "\n");
#else
        fprintf(stderr, "RECV %s %s:\t %u %s\n", 
            FitSec_Name(e), tn, (unsigned int)(info->generationTime / 1000 - _beginTime),
                _signer_types[info->signerType]);
#endif
    }
    return ret;
}

static void print_x(FILE * f, const char * const ptr, int len)
{
    const unsigned char * p = (const unsigned char *)ptr;
    const unsigned char * e = p + len;
    for (; p < e; p++){
        fprintf(f, "%02X", *p);
    }
}
