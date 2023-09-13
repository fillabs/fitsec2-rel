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
static unsigned int _msg_count = 1000;
static float _rate = 10; // 10Hz

char * _storage = "POOL_1";
char* _curStrTime = NULL;

static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "1",  "pool1",    COPT_STR,      &_storage,     "Storage directory 1"   },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },
    { "r",  "rate",     COPT_FLOAT,    &_rate,        "Message rate in Hz" },
    { "n",  "count",    COPT_ULONG,    &_msg_count,   "Message count" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);
int strpdate(const char* s, struct tm* t);                // defined in utils.c

static char _defaultPayload[] = "1234567890";

int main(int argc, char** argv)
{
    FitSec* e;

    FitSecConfig_InitDefault(&cfg);
    cfg.flags |= FS_ALLOW_CERT_DUPLICATIONS;

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

    e = FitSec_New(&cfg, "1");

    if (0 >= loadCertificates(e, _curTime, _storage)) {
        return -1;
    }

    char buf[1024];

    FSMessageInfo m = { 0 };
    uint64_t duration;

    // check preparation time
    struct timeval beg, end;
    size_t len;
    m.sign.ssp.aid = 36;                    // CAM 
    m.sign.ssp.sspData.bits.version = 1;    // version is required. All SSP bits are set to zero. No special container
    m.payloadType = FS_PAYLOAD_SIGNED; // can be skipped. hardcoded for CAM  
    m.message = buf;
    m.generationTime = _curTime;
    m.position = _position;
    gettimeofday(&beg, NULL);
    for (unsigned int i = 0; i < _msg_count; i++) {
        m.messageSize = sizeof(buf);
        m.sign.signerType = FS_SI_AUTO; // reset
        m.generationTime = _curTime + (FSTime64)(1000000.0 * i / _rate);
        len = FitSec_PrepareSignedMessage(e, &m);
        if (len == 0) {
            fprintf(stderr, "SEND %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), i, m.status, FitSec_ErrorMessage(m.status));
            continue;
        }
        if (m.sign.cert == NULL) {
            fprintf(stderr, "SEND %s %2u:\t ERROR: signing certificate not found\n", FitSec_Name(e), i);
            continue;
        }
    }
    gettimeofday(&end, NULL);
    timeval_subtract(&end, &end, &beg);
    duration = ((uint64_t)end.tv_sec) * 1000000 + end.tv_usec;
    fprintf(stderr, "message encoding time %"PRIu64" microsec for %u messages\n", duration/ _msg_count, _msg_count);

    m.payloadSize = sizeof(_defaultPayload);
    memcpy(m.payload, _defaultPayload, m.payloadSize);

    gettimeofday(&beg, NULL);
    for (unsigned int i = 0; i < _msg_count; i++) {
        if (!FitSec_FinalizeSignedMessage(e, &m)) {
            fprintf(stderr, "SEND %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), i, m.status, FitSec_ErrorMessage(m.status));
            continue;
        }
    }
    gettimeofday(&end, NULL);
    timeval_subtract(&end, &end, &beg);
    duration = ((uint64_t)end.tv_sec) * 1000000 + end.tv_usec;
    fprintf(stderr, "message signing time %"PRIu64" microsec for %u messages\n", duration/ _msg_count, _msg_count);

    gettimeofday(&beg, NULL);
    for (unsigned int i = 0; i < _msg_count; i++) {
        m.generationTime = _curTime + (FSTime64)(1000000.0 * i / _rate);
        len = FitSec_ParseMessage(e, &m);
        if (len == 0) {
            fprintf(stderr, "PARS %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), i, m.status, FitSec_ErrorMessage(m.status));
            continue;
        }
    }
    gettimeofday(&end, NULL);
    timeval_subtract(&end, &end, &beg);
    duration = ((uint64_t)end.tv_sec) * 1000000 + end.tv_usec;
    fprintf(stderr, "message parsing time %" PRIu64 " microsec for %u messages\n", duration/ _msg_count, _msg_count);

    gettimeofday(&beg, NULL);
    for (unsigned int i = 0; i < _msg_count; i++) {
        m.generationTime = _curTime + (FSTime64)(1000000.0 * i / _rate);
        if (!FitSec_ValidateSignedMessage(e, &m)) {
            fprintf(stderr, "VALD %s %2d:\t ERROR: 0x%08X %s\n", FitSec_Name(e), i, m.status, FitSec_ErrorMessage(m.status));
            continue;
        }
    }
    gettimeofday(&end, NULL);
    timeval_subtract(&end, &end, &beg);
    duration = ((uint64_t)end.tv_sec) * 1000000 + end.tv_usec;
    fprintf(stderr, "message validation time %" PRIu64 " microsec for %u messages\n", duration/_msg_count, _msg_count);
    
    FitSec_Free(e);

    return 0;
}
