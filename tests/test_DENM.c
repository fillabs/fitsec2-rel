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

static FitSecConfig cfg1, cfg2;

static pchar_t* cfgfile = NULL;

#define ITS_UTC_EPOCH 1072915200

static FS3DLocation position = { 514743600, 56248900, 0 };
static unsigned int _curTime = 0;
static unsigned int _beginTime = 0;
static unsigned int _msg_count = 100;
static float _rate = 1; // 10Hz
static char* _curStrTime = NULL;

FILE * out;

char * outpath  = "msg.log";
char * storage1 = "POOL_1";
char * storage2 = "POOL_2";


static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "C",  "config",   COPT_CFGFILE,  &cfgfile,      "Config file"         },
    { "1",  "pool1",    COPT_STR,      &storage1,     "Storage directory 1"   },
    { "2",  "pool2",    COPT_STR,      &storage2,     "Storage directory 2"   },
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
    "chain",
    "other",
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
int strpdate(const char* s, struct tm* t);                // defined in utils.c
int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);

static bool _onEvent(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    return true;
}
static bool _onSigned(FitSec* e, void* user, FSEventId event, const FSEventParam* params);
static bool _onValidated(FitSec* e, void* user, FSEventId event, const FSEventParam* params);

static char _defaultPayload[] = "1234567890";

static void test_DENM(FitSec* e1, FitSec* e2);

static bool stop_flag = false;
static void* r_thread(void* p)
{
    FitSec** e = (FitSec**)p;

    while (!stop_flag) {
        FitSec_ProceedAsync(e[0]);
        FitSec_ProceedAsync(e[1]);
        sched_yield();
    }

    for (int i = 0; i < 10; ) {
        bool b1 = FitSec_ProceedAsync(e[0]);
        bool b2 = FitSec_ProceedAsync(e[1]);
        if (!b1 && !b2) i++;
        sched_yield();
    }
    return NULL;
}

int main(int argc, char** argv)
{
    FitSec* e[2];

    FitSecConfig_InitDefault(&cfg1);
    FitSecConfig_InitDefault(&cfg2);

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
    e[0] = FitSec_New(&cfg1, "1");
    e[1] = FitSec_New(&cfg2, "2");

    cfg1.cbOnEvent = cfg2.cbOnEvent = _onEvent;
    cfg1.cbOnSigned = cfg2.cbOnSigned = _onSigned;
    cfg1.cbOnValidated = cfg2.cbOnValidated = _onValidated;
    cfg1.cbOnEventUser = e[1];
    cfg2.cbOnEventUser = e[0];

    if (0 >= loadCertificates(e[0], _curTime, storage1)) {
        return -1;
    }
    
    if (0 >= loadCertificates(e[1], _curTime, storage2)) {
        FitSec_Free(e[0]);
        return -1;
    }
//    FitSec_RelinkCertificates(e[0]);
//    FitSec_RelinkCertificates(e[1]);

    // start test thread
#ifdef WIN32
    HANDLE _thr;
    DWORD  _thrId;
    _thr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)r_thread, e, 0, &_thrId);
#else
    pthread_t _thr;
    pthread_create(&_thr, NULL, r_thread, (void*)e);
#endif

	test_DENM(e[0], e[1]);
    stop_flag = true;

#ifdef WIN32
    WaitForSingleObject(_thr, INFINITE);
    CloseHandle(_thr);
#else
    pthread_join(_thr, NULL);
#endif

    FitSec_Free(e[0]);
    FitSec_Free(e[1]);
    FSMessageInfo_Cleanup();

    return 0;
}
/*
#ifdef __GNUC__
#define __FUNCTION__ __func__
#endif
*/
static void test_DENM(FitSec * e1, FitSec * e2) {

    unsigned int i;
    //int opos = 0;

    _beginTime = _curTime;

    // Send DENMs and read it
    for (i = 0; i < _msg_count; i++) {

        FSMessageInfo* m = FSMessageInfo_Allocate(1024);
        m->sign.ssp.aid = 37;
        m->position = position;
        memset(&m->sign.ssp.sspData, 0, sizeof(m->sign.ssp.sspData));
        m->sign.ssp.sspData.bits.version = 1;
        m->payloadType = FS_PAYLOAD_SIGNED;
        m->generationTime = (((uint64_t)_beginTime) + (uint64_t)(1000.0 * i / _rate)) * 1000000;
        m->sign.signerType = FS_SI_AUTO;

        size_t len = FitSec_PrepareSignedMessage(e1, m);
        if (len > 0) {
            m->payloadSize = sizeof(_defaultPayload);
            memcpy(m->payload, _defaultPayload, m->payloadSize);
            if(!FitSec_FinalizeSignedMessageAsync(e1, m, e2)){
                FSMessageInfo_Free(m);
                fprintf(stderr, "SEND %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e1), __FUNCTION__, m->status, FitSec_ErrorMessage(m->status));
            }
            usleep(10);
        }
    }
}

static bool _onSigned(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    FitSec* e2 = (FitSec*)user;
    FSMessageInfo* ms = (FSMessageInfo*)params;
    if (ms->status != 0) {
        fprintf(stderr, "SEND %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), __FUNCTION__, ms->status, FitSec_ErrorMessage(ms->status));
        return false;
    }
    fprintf(stderr, "SEND %s %s:\t OK %s\n", FitSec_Name(e), __FUNCTION__, _signer_types[ms->sign.signerType]);
    
    FSMessageInfo * m = FSMessageInfo_Allocate(1024);
    FSMessageInfo_SwapBuffers(ms, m);
    if (!FitSec_ParseMessage(e2, m)) {
        fprintf(stderr, "PARS %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e2), __FUNCTION__, m->status, FitSec_ErrorMessage(m->status));
        return false;
    }
    if (m->payloadType != FS_PAYLOAD_SIGNED) {
        m->status = FSERR_MESSAGE | FSERR_PAYLOAD | FSERR_TYPE | FSERR_INVALID;
        fprintf(stderr, "PARS %s %s:\t ERR 0x%08X %s\n", FitSec_Name(e2), __FUNCTION__, m->status, FitSec_ErrorMessage(m->status));
        return false;
    }
    if (!FitSec_ValidateSignedMessageAsync(e2, m, NULL)) {
        FSMessageInfo_Free(m);
        fprintf(stderr, "VALD %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e2), __FUNCTION__, m->status, FitSec_ErrorMessage(m->status));
        return false;
    }
    
    return true;
}

static bool _onValidated(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    FSMessageInfo* m = (FSMessageInfo*)params;
    if (m->status != 0) {
        fprintf(stderr, "VALD %s %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), __FUNCTION__, m->status, FitSec_ErrorMessage(m->status));
        return false;
    }
    fprintf(stderr, "VALID %s %s:\t OK %s\n", FitSec_Name(e), __FUNCTION__, _signer_types[m->sign.signerType]);
    return true;
}
