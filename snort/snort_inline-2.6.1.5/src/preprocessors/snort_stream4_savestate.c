/*
** Copyright (C) 2006 Victor Julien <victor.julien@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* what we are doing in this file all very stream4 specific, so
   im not ashamed to pretend we are internal usage ;-) */
#define _STREAM4_INTERNAL_USAGE_ONLY_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef DEBUG
    #ifndef INLINE
        #define INLINE inline
    #endif
#else
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE
#endif /* DEBUG */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */
#include <time.h>
#include <rpc/types.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "bounds.h"
#include "decode.h"
#include "event.h"
#include "debug.h"
#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "mstring.h"
#include "checksum.h"
#include "log.h"
#include "generators.h"
#include "detect.h"
#include "perf.h"
#include "timersub.h"
#include "ubi_SplayTree.h"
#include "snort.h"
#include "snort_packet_header.h"
#include "event_queue.h"
#include "inline.h"
#include "stream.h" /* we set _STREAM4_INTERNAL_USAGE_ONLY_ above */
#include "snort_stream4_savestate.h"
#include "snort_stream4_session.h"
#include "stream_ignore.h"
#include "stream_api.h"
#include "profiler.h"

#include <errno.h> /* for error reporting on fopen */
#include "sfxhash.h" /* for SFXHASH_NODE and friends */

extern SFXHASH *sessionHashTable;
extern Stream4Data s4data;
extern u_int32_t flush_points[];



/* We must twiddle to align the offset the ethernet header and align
   the IP header on solaris -- maybe this will work on HPUX too.

   VJ: copied from spp_stream4.c
*/
#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif

/* copied as well */
#define FCOUNT 64

/* normal TCP states, copied from spp_stream4.c */
#define CLOSED       0
#define LISTEN       1
#define SYN_RCVD     2
#define SYN_SENT     3
#define ESTABLISHED  4
#define CLOSE_WAIT   5
#define LAST_ACK     6
#define FIN_WAIT_1   7
#define CLOSING      8
#define FIN_WAIT_2   9
#define TIME_WAIT   10


/* if called with path == NULL the connections are printed to the screen.

*/
int DumpStateTable(const char *path)
{
    Session *idx = NULL, *saveidx = NULL;
    char got_one = 1;
    Stream *client = NULL;
    Stream *server = NULL;
    SFXHASH_NODE *lastNode = NULL;
    struct in_addr sip, cip;
    char sipstr[16] = "", cipstr[16] = "";
    u_int32_t dumpcnt = 0,
              skipcnt = 0;
    FILE *fp = NULL;

    //DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"connections in hash: %u (path %s)\n", GetSessionCount(), path););

    idx = (Session *) sfxhash_lru(sessionHashTable);
    if(idx == NULL)
    {
        return 0;
    }

    if(path != NULL)
    {
        fp = fopen(path, "w+");
        if(fp == NULL)
        {
            FatalError("Opening '%s' failed: %s.\n", path, strerror(errno));
            return 0;
        }
        /* add a comment for the meaning of each field */
        fprintf(fp, "# state, start_time, last_session_time, client->ip, "
                    "client->port, client->isn, client->base_seq, "
                    "client->last_ack, client->win_size, client->pkts_sent, "
                    "client->bytes_sent server->ip, server->port, server->isn, "
                    "server->base_seq, server->last_ack, server->win_size, "
                    "server->pkts_sent, server->bytes_sent\n");
    }

    do
    {
        got_one = 0;

        /* check if we already wrote this one to the file.
         * saveidx contains the address of the first idx,
         * so if we encounter it again we have looped the
         * entire hash */
        if(idx != saveidx)

        {
            got_one = 1;

            client = &idx->client;
            server = &idx->server;

            /* path is NULL if we just want to print to screen */
            if(path == NULL)
	    {
                cip.s_addr = client->ip;
                sip.s_addr = server->ip;

                strlcpy(cipstr, inet_ntoa(cip), sizeof(cipstr));
                strlcpy(sipstr, inet_ntoa(sip), sizeof(sipstr));

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"connection %s:%u %s:%u\n",
                    cipstr, client->port, sipstr, server->port););
            }
            else
            {
                if((idx->session_flags & SSNFLAG_ESTABLISHED) ||
                   (idx->session_flags & SSNFLAG_MIDSTREAM))
                {
                    /* status */
                    if(idx->session_flags & SSNFLAG_ESTABLISHED)
                        fprintf(fp, "ESTABLISHED ");
                    else if(idx->session_flags & SSNFLAG_MIDSTREAM)
                        fprintf(fp, "MIDSTREAM ");

                    /* timeout */
                    fprintf(fp, "%u %u ", (u_int)idx->start_time,
                                          (u_int)idx->last_session_time);

                    /* client */
                    fprintf(fp, "%u %u %u %u %u %u %u %u ",
                        client->ip, client->port,
                        client->isn, client->base_seq, client->last_ack,
                        client->win_size, client->pkts_sent, client->bytes_sent);

                    /* server */
                    fprintf(fp, "%u %u %u %u %u %u %u %u ",
                        server->ip, server->port,
                        server->isn, server->base_seq, server->last_ack,
                        server->win_size, server->pkts_sent, server->bytes_sent);

                    fprintf(fp, "\n");

                    dumpcnt++;
                }
                else
                {
                    skipcnt++;
                }
            }

            /* save the first idx so we know when our loop is done */
            if(saveidx == NULL)
                saveidx = idx;

            /* move the current node to the front, so our next
               call returns another node. This is different from
               CleanHashTable because there the last node is
               removed */
            lastNode = sfxhash_lru_node(sessionHashTable);
            sfxhash_gmovetofront(sessionHashTable, lastNode);

            idx = (Session *) sfxhash_lru(sessionHashTable);
        }

    } while((idx != NULL) && (got_one == 1));

    if(path != NULL)
    {
        (void)fclose(fp);

        LogMessage("Dumped %u connections to the state file.\n", dumpcnt);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"connections dumped: %u, skipped: %u, "
                            "total: %u\n", dumpcnt, skipcnt, dumpcnt+skipcnt););
    return 0;
}


/* version 1 is currently the only version, but hey, who knows. Maybe
   we need a version 2 soon. */
struct parse_v1_file
{
    char statestr[16]; /* changes should also be done in the below sscanf line */

    /* session */
    u_int32_t session_flags;

    u_int32_t start_time;
    u_int32_t last_session_time;

    /* client */
    u_int32_t c_ip;
    u_int16_t c_port;
    u_int32_t c_isn;
    u_int32_t c_base_seq;
    u_int32_t c_last_ack;
    u_int16_t c_win_size;
    u_int32_t c_pkts_sent;
    u_int32_t c_bytes_sent;

    /* server */
    u_int32_t s_ip;
    u_int16_t s_port;
    u_int32_t s_isn;
    u_int32_t s_base_seq;
    u_int32_t s_last_ack;
    u_int16_t s_win_size;
    u_int32_t s_pkts_sent;
    u_int32_t s_bytes_sent;
};


/* for creating a new session based on the information in the
   file we need to fill a Packet structure with data and pass
   that to GetNewSession(). */
static void InitFakePkt(Packet *p)
{
    p->pkth = calloc(sizeof(SnortPktHeader)+
                              ETHERNET_HEADER_LEN +
                              SPARC_TWIDDLE + IP_MAXPACKET,
                              sizeof(char));

    p->pkt = ((u_int8_t *)p->pkth) + sizeof(SnortPktHeader);
    p->eh = (EtherHdr *)((u_int8_t *)p->pkt + SPARC_TWIDDLE);
    p->iph =
        (IPHdr *)((u_int8_t *)p->eh + ETHERNET_HEADER_LEN);
    p->tcph = (TCPHdr *)((u_int8_t *)p->iph + IP_HEADER_LEN);

    p->data = (u_int8_t *)p->tcph + TCP_HEADER_LEN;

    /* stream_pkt->data is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + TCP_HEADER_LEN + ETHERNET_HEADER_LEN)
     *  in size
     *
     * This is MAX_STREAM_SIZE
     */

    p->eh->ether_type = htons(0x0800);
    SET_IP_VER(p->iph, 0x4);
    SET_IP_HLEN(p->iph, 0x5);
    p->iph->ip_proto = IPPROTO_TCP;
    p->iph->ip_ttl   = 0xF0;
    p->iph->ip_len = 0x5;
    p->iph->ip_tos = 0x10;

    SET_TCP_OFFSET(p->tcph,0x5);
    p->tcph->th_flags = TH_PUSH|TH_ACK;
}


/* return 1 if parsed correctly and within timeout limit
   else 0
 */
static char parse_one_v1(u_int32_t thetime, Packet *fakep, struct parse_v1_file *parse)
{
    Session *ssn;
    u_int8_t fpi;            /* flush point index */
    static u_int8_t savedfpi; /* current flush point index */

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"lets handle the parse struct\n"););

    /* first check for the timeout value, so we
       don't add sessions that have already timed
       out */
    if(parse->last_session_time + s4data.timeout < thetime)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"session already timed out\n"););
        return 0;
    }

    parse->session_flags |= SSNFLAG_SEEN_CLIENT;
    parse->session_flags |= SSNFLAG_SEEN_SERVER;

    if(strcmp(parse->statestr, "ESTABLISHED") == 0)
        parse->session_flags |= SSNFLAG_ESTABLISHED;
    else if(strcmp(parse->statestr, "MIDSTREAM") == 0)
        parse->session_flags |= SSNFLAG_MIDSTREAM;

#ifdef DEBUG
    /* status */
    if(parse->session_flags & SSNFLAG_ESTABLISHED)
        fprintf(stdout, "ESTABLISHED ");
    else if(parse->session_flags & SSNFLAG_MIDSTREAM)
        fprintf(stdout, "MIDSTREAM ");
    else
    {
        return 0;
    }

    /* timeout */
    fprintf(stdout, "%u %u ", (u_int)parse->start_time,
                              (u_int)parse->last_session_time);

    /* client */
    fprintf(stdout, "%u %u %u %u %u %u %u %u ",
        parse->c_ip, parse->c_port,
        parse->c_isn, parse->c_base_seq, parse->c_last_ack,
        parse->c_win_size, parse->c_pkts_sent, parse->c_bytes_sent);

    /* server */
    fprintf(stdout, "%u %u %u %u %u %u %u %u ",
        parse->s_ip, parse->s_port,
        parse->s_isn, parse->s_base_seq, parse->s_last_ack,
        parse->s_win_size, parse->s_pkts_sent, parse->s_bytes_sent);

    fprintf(stdout, "\n");
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"cip: 0x%X cp: %d sip: 0x%X sp: %d\n", 
        parse->c_ip, parse->c_port, parse->s_ip, parse->s_port););

    /* setup the fake packet so GetNewSession can create a 
       hash key from it.

       Note: we don't set the time since a the time is only
       used in CleanHashTable. Since we operate in a empty hash
       the time is not needed.
     */
    fakep->iph->ip_src.s_addr = parse->c_ip;
    fakep->iph->ip_dst.s_addr = parse->s_ip;
    fakep->tcph->th_sport = htons(parse->c_port);
    fakep->tcph->th_dport = htons(parse->s_port);
    fakep->pkth->ts.tv_sec = 0;

    /* Get the session and set it up. */
    ssn = GetNewSession(fakep);

    ssn->client.seglist = ssn->client.seglist_tail = NULL;
    ssn->server.seglist = ssn->server.seglist_tail = NULL;

//    if(s4data.reassemble_server)
//        (void)ubi_trInitTree(&ssn->server.data, /* ptr to the tree head */
//                               DataCompareFunc, /* comparison function */
//                               ubi_trDUPKEY);   /* allow duplicate keys */
//    else
//        ssn->server.data.root = NULL;

//    if(s4data.reassemble_client)
//        (void)ubi_trInitTree(&ssn->client.data, /* ptr to the tree head */
//                                   DataCompareFunc, /* comparison function */
//                                   ubi_trDUPKEY);   /* allow duplicate keys */
//    else
//        ssn->client.data.root = NULL;

    /* session */
    ssn->session_flags = parse->session_flags;
    ssn->start_time = parse->start_time;
    ssn->last_session_time = parse->last_session_time;
    /* assign a psuedo random flush point */
    savedfpi++;
    fpi = savedfpi % FCOUNT;
    ssn->flush_point = flush_points[fpi];
    printf("fpi %u, %u\n", fpi, flush_points[fpi]);

    /* client */
    ssn->client.state = ESTABLISHED;
    ssn->client.ip = parse->c_ip;
    ssn->client.port = parse->c_port;
    ssn->client.isn = parse->c_isn;
    ssn->client.base_seq = parse->c_base_seq;
    ssn->client.last_ack = parse->c_last_ack;
    ssn->client.win_size = parse->c_win_size;
    ssn->client.pkts_sent = parse->c_pkts_sent;
    ssn->client.bytes_sent = parse->c_bytes_sent;

    /* server */
    ssn->server.state = ESTABLISHED;
    ssn->server.ip = parse->s_ip;
    ssn->server.port = parse->s_port;
    ssn->server.isn = parse->s_isn;
    ssn->server.base_seq = parse->s_base_seq;
    ssn->server.last_ack = parse->s_last_ack;
    ssn->server.win_size = parse->s_win_size;
    ssn->server.pkts_sent = parse->s_pkts_sent;
    ssn->server.bytes_sent = parse->s_bytes_sent;

    return 1;
}


int LoadStateTable(const u_int32_t thetime, const char *path)
{
    FILE *fp = NULL;
    char buf[512]  = "", version[16] = ""; /* if you change the length of
                                              version, also change it in the
                                              sscanf string below */
    int res = 0;
    struct parse_v1_file parse;
    u_int32_t loadcnt = 0;
    u_int32_t skipcnt = 0;
    Packet fakepkt;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"start\n"););

    /* initialization */
    InitFakePkt(&fakepkt);
    memset(&parse, 0, sizeof(parse));

    /* open the file. No fatal error, because the first time this option
       is enabled we dont have a file yet. */
    fp = fopen(path, "r");
    if(fp == NULL)
    {
        printf("Opening '%s' failed: %s.\n", path, strerror(errno));
        return 0;
    }

    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"got line %s", buf););

        if(buf[0] != '#')
        {
            /* Session part
               1. string state flag: ESTABLISHED or MIDSTREAM
               2. session start time
               3. session last_session_time

               Client part
               4. ip  5. port  6. isn  7. base_seq  8. last_ack  9. win_size
                 10. pkts_sent  11. bytes_sent

               Server part
               12. ip  13. port  14. isn  15. base_seq  16. last_ack  17. win_size
                 18. pkts_sent  19. bytes_sent

                               1    2  3  4  5   6  7  8  9   10 11 12 13  14 15 16 17  18 19 */
            res = sscanf(buf, "%15s %u %u %u %hu %u %u %u %hu %u %u %u %hu %u %u %u %hu %u %u",
                              parse.statestr, &parse.start_time, &parse.last_session_time,
                                  &parse.c_ip, &parse.c_port, &parse.c_isn, &parse.c_base_seq,
                                  &parse.c_last_ack, &parse.c_win_size, &parse.c_pkts_sent,
                                  &parse.c_bytes_sent,

                                  &parse.s_ip, &parse.s_port, &parse.s_isn, &parse.s_base_seq,
                                  &parse.s_last_ack, &parse.s_win_size, &parse.s_pkts_sent,
                                  &parse.s_bytes_sent);
            if(res == 19)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"scanf likes the line\n"););

                if(parse_one_v1(thetime, &fakepkt, &parse) == 1)
	        {
                    pc.tcp_streams++;
                    loadcnt++;
	        }
	        else
	        {
                    skipcnt++;
	        }
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"scanf did not like the line\n"););

                res = sscanf(buf, "%15s", version);
                if(res == 1)
                {
                    if(strncmp(version,"version", 7) == 0)
                    {
                        /* we dont do anything with it, but dont want
                           to increase skipcnt for it either */
                    }
                    else
                    {
                        skipcnt++;
                    }
                }
                else
                {
                    skipcnt++;
                }
            }
        }
    }

    fclose(fp);

    LogMessage("Loaded %u connections from the state file.\n", loadcnt); 

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"end: loadcnt %u, skipcnt: %u, total: %u\n",
                            loadcnt, skipcnt, loadcnt+skipcnt););
    return 0;
}

