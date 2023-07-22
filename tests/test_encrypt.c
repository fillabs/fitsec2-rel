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
#include <inttypes.h>
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
static uint64_t     _beginTime = 0;
static unsigned long _msg_count = 100;

FILE * out;

char * outpath  = "msg.log";
char * storage1 = "POOL_C1";
char * storage2 = "POOL_C2";
char* _curStrTime = NULL;


static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"  },
    { "C",  "config",   COPT_CFGFILE,  &cfgfile,      "Config file"           },
    { "1",  "pool1",    COPT_STR,      &storage1,     "Storage directory 1"   },
    { "2",  "pool2",    COPT_STR,      &storage2,     "Storage directory 2"   },
    { "o",  "out",      COPT_STR,      &outpath,      "Output path" },
    { "n",  "count",    COPT_ULONG,    &_msg_count,   "Message count" },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

int strpdate(const char* s, struct tm* t);                // defined in utils.c
int loadCertificates(FitSec * e, const pchar_t * _path);

static void test_encrypt(FitSec* e1, FitSec* e2);

static FitSecAppProfile _Profiles[] = {
    {	{FITSEC_AID_CAM,    3}, 990, 0	},
    {	{FITSEC_AID_DENM,   4}, 0,   0	},
    {	{FITSEC_AID_GNMGMT, 0}, 0,   0	},
    {	{FITSEC_AID_ANY,    0}, 0,   0	}
};

int main(int argc, char** argv)
{
    FitSec* e[2];

    FitSecConfig_InitDefault(&cfg1);
    FitSecConfig_InitDefault(&cfg2);
    cfg1.appProfiles = &_Profiles[0];
    cfg2.appProfiles = &_Profiles[0];

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
        out = NULL;
    }

    // setup crypto alg

    e[0] = FitSec_New(&cfg1, "1");
    e[1] = FitSec_New(&cfg2, "2");
    
    if (0 >= loadCertificates(e[0], storage1)) {
        return -1;
    }
    
    if (0 >= loadCertificates(e[1], storage2)) {
        FitSec_Free(e[0]);
        return -1;
    }
    FitSec_RelinkCertificates(e[0]);
    FitSec_RelinkCertificates(e[1]);

    test_encrypt(e[0], e[1]);

    FitSec_Free(e[0]);
    FitSec_Free(e[1]);
    FSMessageInfo_Cleanup(); 
    return 0;
}

static void  test_encrypt(FitSec* e1, FitSec* e2) {
    char buf[1024];

    //	int opos = 0;
    FSMessageInfo ms = { 0 };
    FSMessageInfo_SetBuffer(&ms, buf, sizeof(buf));

    _beginTime = _curTime;

    ms.ssp.aid = FITSEC_AID_CAM;
    ms.position = position;
    ms.ssp.sspData.bits.version = 1;
    ms.payloadType = FS_PAYLOAD_SIGNED;
    ms.generationTime = ((FSTime64)_beginTime) * 1000000;

//    FSHashedId8 tgt1 = FitSec_CertificateDigest(FitSec_CurrentCertificate(e1, ms.ssp.aid));
    FSHashedId8 tgt2 = FitSec_CertificateDigest(FitSec_CurrentCertificate(e2, ms.ssp.aid));

    FitSec_PrepareEncryptedMessage(e1, &ms, 1, &tgt2);
    for (int i = 0; i < 256; i++) {
        ms.payload[i] = (char)i;
    }
    ms.payloadSize = 256;
    if(0 == FitSec_FinalizeEncryptedMessage(e1, &ms)){
        fprintf(stderr, "Encryption error: %s\n", FitSec_ErrorMessage(ms.status));
    }else{
        size_t len = FitSec_ParseMessage(e2, &ms);
        if(len > 0){
            FitSec_DecryptMessage(e2, &ms);
            if (ms.payloadSize != 256) {
                fprintf(stderr, "Payload size mismatch\n");
            }
            else {
                for (int i = 0; i < ms.payloadSize; i++) {
                    if (ms.payload[i] != (char)i) {
                        fprintf(stderr, "Error on payload position %d\n", i);
                        break;
                    }
                }
            }
        }
        fprintf(stderr, "Done!\n");
    }
}
