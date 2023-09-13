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

#include "cstr.h"
#include "cbyteswap.h"
#include "fitsec.h"
#include "fitsec_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <copts.h>
#include <time.h>
#include <pcap.h>

static pchar_t* _o_cfgfile = NULL;
char *          _o_storage = "POOL_PCAP";
char *          _o_outpath  = "msg.log";
char *          _o_curStrTime = NULL;

static uint64_t     _curTime = 0;

int strpdate(const char* s, struct tm* t);                // defined in utils.c
int loadCertificates(FitSec * e, FSTime32 curTime, const pchar_t * _path);

static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "C",  "config",   COPT_CFGFILE,  &_o_cfgfile,      "Config file"         },
    { "1",  "pool",     COPT_STR,      &_o_storage,      "Storage directory"   },
    { "o",  "out",      COPT_STR,      &_o_outpath,      "Output path"         },
    { "t",  "time",     COPT_STR,      &_o_curStrTime,  "The ISO representation of starting time" },


    { NULL, NULL, COPT_END, NULL, NULL }
};

static char _error_buffer[PCAP_ERRBUF_SIZE];

static void my_packet_handler(
    uint8_t *args,
    const struct pcap_pkthdr *header,
    const uint8_t *packet
);

int main(int argc, char** argv)
{
    FitSecConfig cfg;
    FitSec * e;

#ifdef _MSC_VER
    SetDllDirectory("C:\\Windows\\System32\\Npcap\\");
#endif

    FitSecConfig_InitDefault(&cfg);
    
    argc = coptions(argc, argv, COPT_DEFAULT | COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP, options);
    if (COPT_ERC(argc)) {
        coptions_help(stdout, argv[0], 0, options, " <pcap file>");
        return -1;
    }

    e = FitSec_New(&cfg, "1");

    if(_o_curStrTime){
        struct tm t;
        if(0 > strpdate(_o_curStrTime, &t)){
            fprintf(stderr, "%s: Unknown time format\n", _o_curStrTime);
            return -1;
        }
        _curTime = mkitstime32(&t);
    }else{
        _curTime = unix2itstime64(time(NULL));
    }

    if( 0 >= loadCertificates(e, _curTime, _o_storage)){
	FitSec_Free(e);
        fprintf(stderr, "Load certificates failed\n");
        return 1;
    }

    for (int i=1; i<argc; i++) {
        pcap_t *handle = pcap_open_offline(argv[i], _error_buffer);
        if(NULL == handle){
            fprintf(stderr, "%s: %s\n", argv[i], _error_buffer);
            continue;
        }
        
        pcap_loop(handle, 0, my_packet_handler, (uint8_t*)e);
    }

    FitSec_Free(e);
    return 0;
}

typedef struct GN_BasicHeader GN_BasicHeader;
__PACKED__(struct GN_BasicHeader
{
    uint8_t ver_next;
    uint8_t reserved;
    uint8_t lifetime;
    uint8_t hlimit;
    uint8_t next;
});

typedef struct EtherHeader EtherHeader;
__PACKED__(struct EtherHeader
{
    uint8_t   dhost[6];
    uint8_t   shost[6];
    uint16_t  type;
    uint8_t   next;
});

static void my_packet_handler(
    uint8_t *args,
    const struct pcap_pkthdr *header,
    const uint8_t *packet
)
{
    FitSec * e = (FitSec *)args;

    const EtherHeader * eth_header = (const EtherHeader*) packet;
    if (eth_header->type == 0x4789) { // GN inverted
        const GN_BasicHeader * gnbh = (const GN_BasicHeader *)&eth_header->next;
        if((gnbh->ver_next & 0x0f) == 0x02) {
            // secured header
            FSMessageInfo m = {0};
//            memset(&m, 0, sizeof(m));
            m.message = (char*)&gnbh->next;
            m.messageSize = header->caplen - (m.message - (char*)packet);
            m.generationTime = _curTime;

            size_t rc = FitSec_ParseMessage(e, &m);
            if(rc >=0){
                if(FitSec_ValidateSignedMessage(e, &m)){
                    return;
                }
            }
            fprintf(stderr, "error: %s\n", FitSec_ErrorMessage(m.status));
        }
    }
}
