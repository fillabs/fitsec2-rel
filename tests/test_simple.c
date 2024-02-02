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

static FitSecConfig cfg;

static FS3DLocation _position = { 514743600, 56248900, 0 };
static FSTime64 _curTime = 0;
static unsigned int _msg_count = 100;
static float _rate = 10; // 10Hz

char * _storage1 = "POOL_1";
char * _storage2 = "POOL_2";
char* _curStrTime = NULL;

char * _out = NULL;

static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "1",  "pool1",    COPT_STR,      &_storage1,     "Storage directory 1"   },
    { "2",  "pool2",    COPT_STR,      &_storage2,     "Storage directory 2"   },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },
    { "r",  "rate",     COPT_FLOAT,    &_rate,        "Message rate in Hz" },
    { "n",  "count",    COPT_ULONG,    &_msg_count,   "Message count" },
    { "o",  "out",      COPT_STR,      &_out,         "Log messages in file" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

static const char* _signer_types[] = {
    "self",
    "digest",
    "certificate",
    "none",
};

int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);
int strpdate(const char* s, struct tm* t);                // defined in utils.c

static char _defaultPayload[] = "1234567890";

int main(int argc, char** argv)
{
    FitSec* es, * er;

    FitSecConfig_InitDefault(&cfg);
    cfg.flags |= FS_ALLOW_CERT_DUPLICATIONS;
    FILE * out = NULL;

    int flags = COPT_DEFAULT | COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP;
    argc = coptions(argc, argv, flags, options);
    if (COPT_ERC(argc)) {
        coptions_help(stdout, argv[0], 0, options, "Test");
        return -1;
    }

    if (_curStrTime) {
        struct tm t;
        if (0 > strpdate(_curStrTime, &t)) {
            fprintf(stderr, "%s: Unknown time format\n", _curStrTime);
            return -1;
        }
        _curTime = mkitstime64(&t);
    }
    else {
        _curTime = unix2itstime64(time(NULL));
    }
    if(_out){
        out = fopen(_out, "wb");
        if(out == NULL){
            perror(_out);
        }
    }

    es = FitSec_New(&cfg, "1");
    er = FitSec_New(&cfg, "2");

    if (0 >= loadCertificates(es, _curTime, _storage1)) {
        return -1;
    }

    if (0 >= loadCertificates(er, _curTime, _storage2)) {
        FitSec_Free(es);
        return -1;
    }

//    FitSec_RelinkCertificates(es);
//    FitSec_RelinkCertificates(er);

    char buf[1024];

    //	int opos = 0;
    FSMessageInfo ms = { 0 }, mr = { 0 };

    for (unsigned int i = 0; i < _msg_count; i++) {
        size_t len;

        ms.sign.ssp.aid = 36;                    // CAM 
        ms.sign.ssp.sspData.bits.version = 1;    // version is required. All SSP bits are set to zero. No special container
        ms.payloadType = FS_PAYLOAD_SIGNED; // can be skipped. hardcoded for CAM  

        // Prepare message buffer
        // Fitsec will put the security header in the provided buffer
        // GN Basic Header shall be already put before the security header
        // GN Common Header, GN Extended Header, BTP and facility message shall be put to the buffer as a payload between Prepare and Finalize steps
        ms.message = buf;
        ms.messageSize = sizeof(buf);
        // generation time is needed here to select proper certificate
        ms.generationTime = _curTime + (FSTime64)(1000000.0 * i / _rate);
        // position is needed to select certificate. Otherwise only certificates without region restriction can be selected
        ms.position = _position;
        ms.sign.signerType = FS_SI_AUTO; // reset

        len = FitSec_PrepareSignedMessage(es, &ms);
        if (len == 0) {
            fprintf(stderr, "SEND %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(es), i, ms.status, FitSec_ErrorMessage(ms.status));
            continue;
        }
        if (ms.sign.cert == NULL) {
            fprintf(stderr, "SEND %s %2u:\t ERROR: signing certificate not found\n", FitSec_Name(es), i);
            continue;
        }

        // fill payload
        // the payload shall contain GN common header, GN extended header, BTP and facility(CAM, DENM, whatever)
        // here only the dummy payload is used
        ms.payloadSize = sizeof(_defaultPayload);
        memcpy(ms.payload, _defaultPayload, ms.payloadSize);

        // fill-in message headers and sign message
        if (!FitSec_FinalizeSignedMessage(es, &ms)) {
            fprintf(stderr, "SEND %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(es), i, ms.status, FitSec_ErrorMessage(ms.status));
            continue;
        }
        fprintf(stderr, "SEND %s %2u:\t OK %s\n", FitSec_Name(es), i, _signer_types[ms.sign.signerType]);

        if(out){
            fwrite(ms.message, 1, ms.messageSize, out);
            fflush(out);
        }
        // RECEIVE MESSAGE
        memset(&mr, 0, sizeof(mr)); // reset it
        // set message buffer
        mr.message = ms.message;
        mr.messageSize = ms.messageSize;
        mr.generationTime = _curTime + (FSTime64)(1000000.0 * i / _rate);
        len = FitSec_ParseMessage(er, &mr);
        if (len == 0) {
            fprintf(stderr, "PARS %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(er), i, mr.status, FitSec_ErrorMessage(mr.status));
            continue;
        }
        if (!FitSec_ValidateSignedMessage(er, &mr)) {
            fprintf(stderr, "VALD %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(er), i, mr.status, FitSec_ErrorMessage(mr.status));
            continue;
        }
        fprintf(stderr, "RECV %s %2d:\t OK %s\n", FitSec_Name(er), i, _signer_types[mr.sign.signerType]);
        // CHECK IT

        if (ms.payloadSize != mr.payloadSize) {
            fprintf(stderr, "CHCK   %2d:\t ERROR: payload size mismatch\n", i);
            continue;
        }
        if (memcmp(ms.payload, mr.payload, ms.payloadSize)) {
            fprintf(stderr, "CHCK   %2d:\t ERROR: payload mismatch\n", i);
            continue;
        }
    }
    FitSec_Free(es);
    FitSec_Free(er);

    return 0;
}
