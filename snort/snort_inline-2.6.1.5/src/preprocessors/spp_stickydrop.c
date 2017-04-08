/* $Id: spp_template.c,v 1.5 2004/02/13 16:19:03 roesch Exp $ */
/* Snort Preprocessor Plugin Source File Template */

/* spp_stickydrop 
 *
 * Purpose:
 *
 * Sticky Drop is a simple packet filter that drops packets based on a timeout 
 * specified by the user through the sticky-drop rule keyword, or through special
 * options added to preprocessors.   
 *
 *
 * Arguments:
 *
 * Ummmmmm nil at the moment, will add a whitlist or never drop list
 * Effect:
 *
 * Drop packets from people we don't like because they are messing with our stuff.
 *
 *
 */

/* stickydrop is for inline */
#ifdef GIDS


#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>
#include "generators.h"
#include "event_wrapper.h"
#include "assert.h"
#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "mempool.h"
#include "plugbase.h"
#include "mstring.h"
#include "util.h"
#include "log.h"
#include "parser.h"
#include "detect.h"
#include "rules.h"
#include "decode.h"
#include "debug.h"
#include "ubi_SplayTree.h"
#include "ubi_BinTree.h"
#include "profiler.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#include "spp_stickydrop.h"
#include "inline.h"

#define MAX_PORTS		64
#define MEM_CHUNK		32
#define DIRECTION_SOURCE	0
#define DIRECTION_DST		1

/* Data Used for Sticky Drop */
typedef struct _StickyD
{
    ubi_trRoot attackerRoot;  /* this tree is for the blocker ip addy's */
    ubi_trRootPtr attackerRootPtr;
    MemPool AttackerPool;
    u_int32_t max_block_entries;
    char log;
    FILE *logfile;
    char *logpath;

} StickyD;

StickyD stickd;


typedef struct _Attacker
{
    ubi_trNode Node;             /* for the splay tree */
    MemBucket *bucket;
    u_int32_t ip;
    u_int32_t timeout;
    struct timeval blocktime;
    struct timeval unblocktime;

} Attacker;

Attacker attacker;

typedef struct _sdhostNode
{
    IpAddrSet *address;
    u_short hsp;         /* hi src port */
    u_short lsp;         /* lo src port */
    u_int32_t flags;     /* control flags */
    struct _sdhostNode *nextNode;

} sdHostNode;

sdHostNode *sdignoreList; /* for ignore-hosts */
int num_ports_from;
int num_ports_to;
u_int32_t *sdignorePortFrom;
u_int32_t *sdignorePortTo;


static void StickyDropInit(u_char *);
static void ParseStickyDropArgs(char *);
void StickyDrop(Packet *, void *);
void SDLog(Packet *);
static int IpAddressCompareFunction(ubi_trItemPtr, ubi_trNodePtr);
static int PruneAttackers(u_int32_t now, int tokill, Attacker *saveme);
static void PreprocCleanExitFunction(int, void *);
static void PreprocRestartFunction(int, void *);

/* For portscan args */
static void sdInitTimeouts(u_char *);
static void ParseSDTimeoutArgs(char *);
 
/* For ignore hosts */
void sdInitIgnoreHosts(u_char *);
IpAddrSet* sdIgnoreAllocAddrNode(sdHostNode *);
void sdScanParseIp(char *, sdHostNode *);

/* For ignore ports */
void sdInitIgnoreFrom(u_char *);
void sdInitIgnoreTo(u_char *);
void sdInitIgnorePorts(u_char *, u_int32_t **, int *);
u_int32_t sdScanParsePort(char *);

int sdIsIgnored(Packet *, char);
int sdBlockTreeSearch(Packet *, char);

static int s_stickyd_running = 0;
 
SDtimeout sdt;

#ifdef PERF_PROFILING
PreprocStats sdPerfStats;
#endif

/*
 * Function: SetupStickyDrop()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupStickyDrop()
{
    /* 
     * link the preprocessor keyword to the init function in 
     * the preproc list 
     */
    RegisterPreprocessor("stickydrop", StickyDropInit);
    RegisterPreprocessor("stickydrop-timeouts",sdInitTimeouts);
    RegisterPreprocessor("stickydrop-ignorehosts", sdInitIgnoreHosts);
    RegisterPreprocessor("stickydrop-ignoreports-from", sdInitIgnoreFrom);
    RegisterPreprocessor("stickydrop-ignoreports-to", sdInitIgnoreTo);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: StickyDrop is setup...\n"););
}


/*
 * Function: StickyDropInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void StickyDropInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: StickyDrop Initialized\n"););

    memset(&stickd, 0, sizeof(StickyD));
    ParseStickyDropArgs(args);
    stickd.attackerRootPtr = &stickd.attackerRoot;

    ubi_trInitTree(stickd.attackerRootPtr, IpAddressCompareFunction, 0);
    if(mempool_init(&stickd.AttackerPool , stickd.max_block_entries, sizeof(Attacker)))
    {
      FatalError("ERROR: Could not alloc memory for stickydrop entries\n");
    }
    else if(!InlineMode()) 
    {
      FatalError("ERROR: We have to be in InlineMode() to use stickydrop\n"); 
    }

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("sticky-drop", &sdPerfStats, 0, &totalPerfStats);
#endif

    s_stickyd_running = 1;
    AddFuncToPreprocList(StickyDrop, PRIORITY_NETWORK, PP_STICKYDROP);
    AddFuncToPreprocCleanExitList(PreprocCleanExitFunction, NULL, PRIORITY_FIRST, PP_STICKYDROP);
    AddFuncToPreprocRestartList(PreprocRestartFunction, NULL, PRIORITY_FIRST, PP_STICKYDROP);

    /* fire up the stickyd output plugin */
    ActivateOutputPlugin("alert_StickyD",NULL);

}


/*
 * Function: ParseStickyDropArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
static void ParseStickyDropArgs(char *args)
{
    int num_toks, s_toks;
    char **toks = NULL;
    char **stoks;
    int i;
    char* index;
    char logpath[STD_BUF], tmp[STD_BUF];

    /* setup the defaults */
    strlcpy(logpath, pv.log_dir, STD_BUF);
    strlcpy(tmp, "/stickyd.log", STD_BUF);
    strlcat(logpath, tmp, STD_BUF);

    stickd.max_block_entries = 5000;
    stickd.log = 0;
    if (args)
    {

        toks = mSplit(args, ",", 5, &num_toks, 0);

        i=0;

        while (i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 4, &s_toks, 0);
            if(!strcasecmp(stoks[0], "max_entries"))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /* number of tgtnodes */
                    stickd.max_block_entries = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("Bad Sticky-Drop Max Entries Arg",file_name,file_line);
                }
    
            }
            else if(!strcasecmp(stoks[0], "log"))
            {
                stickd.log = 1;
                i++;
            } 
            else if(!strcasecmp(stoks[0], "log-file"))
            {
                if(isascii((int)(stoks[1][0])))
                {
                    if (stoks[1][0] == '/')
                        strlcpy (logpath, stoks[1], STD_BUF);
                    else
                    {
                        strlcpy(logpath, pv.log_dir, STD_BUF);
                        strlcat(logpath, "/", STD_BUF);
                        strlcat(logpath, stoks[1], STD_BUF);
                    }
                    i++;
                }
                else
                {
                    FatalError(" %s(%d) => '%s' has invalid value '%s'. ",
                                file_name, file_line,
                               stoks[0], stoks[1]);
                }
            }
            else
            {
                FatalError("%s(%d) => option '%s' is undefined. ",
                            file_name, file_line, stoks[0]);
            }

            mSplitFree(&stoks, s_toks);
        }
        mSplitFree(&toks, num_toks);

    }
    if(stickd.log)
    {
        stickd.logfile = fopen(logpath, "a+");

        if(stickd.logfile == NULL)
        {
            FatalError("Can't open logfile: %s", stickd.logpath);
        }
    }
}


static void sdInitTimeouts(u_char *targs)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: stickydrop-timeouts Initialized\n"););

    ParseSDTimeoutArgs(targs);
}


static void ParseSDTimeoutArgs(char *targs)
{
    int num_toks, s_toks;
    char **toks = NULL;
    char **stoks;
    int i;
    char* index;

    sdt.sfportscan = 0;
//    sdt.portscan2 = 0 ;
    sdt.clamav = 0;

    if (targs)
    {

        toks = mSplit(targs, ",", 4, &num_toks, 0);

        i=0;

        while (i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 1, &s_toks, 0);
            if(!strcasecmp(stoks[0], "sfportscan"))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /* in the immortal words of socrates, "I drank what" */
                    sdt.sfportscan = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("Bad Sticky-Drop sfportscan timeout entry",file_name,file_line);
                }

            }
//            else if(!strcasecmp(stoks[0], "portscan2"))  
//            {
//                if(isdigit((int)(stoks[1][0])))            
//                {
                    /* in the immortal words of socrates, "I drank what" */
//                    sdt.portscan2 = atoi(stoks[1]);  
//                    i++;
//                }
//                else
//                {
//                    FatalError("Bad Sticky-Drop portscan2 timeout entry",file_name,file_line);  
//                }
//            }
            else if(!strcasecmp(stoks[0], "clamav"))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /* in the immortal words of socrates, "I drank what" */
                    sdt.clamav = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("Bad Sticky-Drop clamav timeout entry",file_name,file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => option '%s' is undefined. ",
                            file_name, file_line, stoks[0]);
            }

            mSplitFree(&stoks, s_toks);
        }
        mSplitFree(&toks, num_toks);

    }
}


void sdInitIgnoreHosts(u_char *hosts)
{
    char **toks;
    int num_toks;
    int num_hosts = 0;
    sdHostNode *sdcurrentHost;
    /*int i;*/

    sdcurrentHost = NULL;
    sdignoreList = NULL;

    if(hosts == NULL)
    {
        ErrorMessage(" ERROR: %s(%d)=> No arguments to "
                     "stickydrop-ignorehosts, ignoring.\n",
                     file_name, file_line);
        return;
    }

    toks = mSplit(hosts, " ", 127, &num_toks, '\\');

    for(num_hosts = 0; num_hosts < num_toks; num_hosts++)
    {
        if((sdcurrentHost = (sdHostNode *) calloc(1, sizeof(sdHostNode))) == NULL)
        {
            FatalError("[!] ERROR: Unable to allocate space for "
                       "sticky-drop IgnoreHost");
        }
        sdcurrentHost->address = NULL; /* be paranoid */
        sdcurrentHost->nextNode = sdignoreList;
        sdignoreList = sdcurrentHost;


        sdScanParseIp(toks[num_hosts], sdcurrentHost);
    }

    mSplitFree(&toks, num_toks);
}


IpAddrSet* sdIgnoreAllocAddrNode(sdHostNode *host)
{
    IpAddrSet *idx;

    if((idx = (IpAddrSet *) calloc(1, sizeof(IpAddrSet))) == NULL)
      {
        FatalError("[!] ERROR: Unable to allocate space for "
                       "stickyd IP addr\n");
      }

    idx->next = host->address;
    host->address = idx;

    return idx;
}


void sdScanParseIp(char *addr, sdHostNode *host)
{
    char **toks;
    int num_toks;
    int i, not_flag;
    IpAddrSet *tmp_addr;
    char *enbracket, *ports;
    char *tmp;

    if(addr == NULL)
    {
        ErrorMessage("ERROR %s(%d) => Undefine address in "
                     "stickydrop-ignorehosts directive, igoring.\n", file_name,
                     file_line);

        return;
    }

    if(*addr == '!')
    {
        host->flags |= EXCEPT_SRC_IP;
        addr++;
    }

    if(*addr == '$')
    {
        if((tmp = VarGet(addr + 1)) == NULL)
        {
            ErrorMessage("ERROR %s (%d) => Undefined variable \"%s\", "
                         "ignoring\n", file_name, file_line, addr);

            return;
        }
    }
    else
    {
        tmp = addr;
    }

    ports = strrchr(tmp, (int)'@');

    if (*tmp == '[')
    {
        enbracket = strrchr(tmp, (int)']');
        if (enbracket) *enbracket = '\x0'; /* null out the en-bracket */

        if (ports && enbracket && (ports < enbracket))
        {
          FatalError("[!] ERROR %s(%d) => syntax error in"
                     "stickydrop-ignorehosts \"%s\"\n",
                     file_name, file_line, tmp);
        }
        toks = mSplit(tmp+1, ",", 128, &num_toks, 0);

        for(i = 0; i < num_toks; i++)
        {
            tmp_addr = sdIgnoreAllocAddrNode(host);

            ParseIP(toks[i], tmp_addr);
        }

        mSplitFree(&toks, num_toks);
    }
    else
    {
        if (ports) *ports = '\x0'; /* null out the at */

        tmp_addr = sdIgnoreAllocAddrNode(host);
        ParseIP(tmp, tmp_addr);
    }

    if (ports)
    {
      ports++;
      if (ParsePort(ports, &(host->hsp), &(host->lsp), "ip", &not_flag))
        host->flags |= ANY_SRC_PORT;
      if (not_flag)
        host->flags |= EXCEPT_SRC_PORT;
    } else {
        host->flags |= ANY_SRC_PORT;
    }

}


void sdInitIgnoreFrom(u_char *args)
{
  sdInitIgnorePorts(args, &sdignorePortFrom, &num_ports_from);
}


void sdInitIgnoreTo(u_char *args)
{
  sdInitIgnorePorts(args, &sdignorePortTo, &num_ports_to);
}


void sdInitIgnorePorts(u_char *list, u_int32_t **ports, int *num)
{
    int new_ports, max_ports;
    u_int32_t *pool;
    char **toks;
    int num_toks;

    *ports = NULL;
    *num = 0;
    max_ports = 0;

    if(list == NULL)
    {
        ErrorMessage(" ERROR: %s(%d)=> No arguments to "
                     "stickydrop-ignoreports, ignoring.\n",
                     file_name, file_line);
        return;
    }

    toks = mSplit(list, " ", MAX_PORTS, &num_toks, '\\');

    for(;*num < num_toks; (*num)++)
    {
      if(*num >= max_ports)
      {
        new_ports = max_ports + MEM_CHUNK;
        if((pool = (u_int32_t *) calloc(new_ports, sizeof(u_int32_t))) == NULL)
        {
          FatalError("[!] ERROR: Unable to allocate space for "
                     "stickydrop-ignoreports");
        }
        if (*ports != NULL)
        {
          memcpy(pool, *ports, max_ports * sizeof(u_int32_t));
          free(*ports);
        }
        max_ports = new_ports;
        *ports = pool;
      }
      (*ports)[*num] = sdScanParsePort(toks[*num]);
    }

    mSplitFree(&toks, num_toks);

}


u_int32_t sdScanParsePort(char *port)
{
    char *tmp;

    if(port == NULL)
    {
      FatalError("ERROR %s(%d) => Undefined ports in "
                 "stickydrop-ignoreports directive\n",
                 file_name, file_line);
    }

    if(*port == '$')
    {
      if((tmp = VarGet(port + 1)) == NULL)
        {
          FatalError("ERROR %s (%d) => Undefined variable \"%s\"\n",
                     file_name, file_line, port);

        }
    }
    else
    {
        tmp = port;
    }

    if(!isdigit((int)tmp[0]))
    {
      FatalError("ERROR %s(%d) => Bad port list to "
                 "stickydrop-ignoreports\n", file_name, file_line);
    }

    return((u_int32_t)atol(tmp));
}


/*
    search the tree for the ipaddresses src or dst in direction 'direction'.

    Returns 1 of the ip is in our list, 0 otherwise.
*/
int sdBlockTreeSearch(Packet *p, char direction)
{
   Attacker tmp;
   Attacker *searchval;
   
   if(direction == DIRECTION_SOURCE) 
   { 
       tmp.ip = (u_int32_t)p->iph->ip_src.s_addr;
      
       DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                  "Going to search for source ip of: of %s\n",inet_ntoa(p->iph->ip_src)););
   }
   else if(direction == DIRECTION_DST)
   {
       tmp.ip = (u_int32_t)p->iph->ip_dst.s_addr;
   
       DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                  "Going to search for source ip of: of %s\n",inet_ntoa(p->iph->ip_dst)););

   }

   searchval = (Attacker *) ubi_sptFind(stickd.attackerRootPtr, (ubi_btItemPtr)&tmp);
 
   if (searchval != NULL)
   {
       /* found, lets inspect the attacker */
	
       /* check the timeout */
       if(p->pkth->ts.tv_sec >= (searchval->unblocktime.tv_sec))
       {
           DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                                   "Pruning out Attacker due to timeout\n"););

           PruneAttackers(p->pkth->ts.tv_sec, 1, NULL);
           
           return(0);
       }
       else if(direction == DIRECTION_SOURCE)
       {
           DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                                   "Attacker %s was found in tree and we haven't past our unblock mark\n",inet_ntoa(p->iph->ip_src)););

           return(1);
       }
       else if(direction == DIRECTION_DST)
       { 
           DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                                   "Attacker %s was found in tree and we haven't past our unblock mark\n",inet_ntoa(p->iph->ip_dst)););

           return(1);
       }          
   }
   else if(direction == DIRECTION_SOURCE) 
   { 
        DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                                "ip address %s not found in block tree\n",inet_ntoa(p->iph->ip_src)););
        
        return(0);
   }
   else if(direction == DIRECTION_DST)
   {
        DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,  
                                "ip address %s not found in block tree passing\n",inet_ntoa(p->iph->ip_dst)););

        return(0); 
   }                

    /* default case: not found */
    return(0);
}


int sdIsIgnored(Packet *p, char dir)
{                 
    sdHostNode *sdcurrentHost = sdignoreList;
    int i;                

    for(i = 0; i < num_ports_from; i++)
    {
      if (p->sp == sdignorePortFrom[i])   
      {
        return(1);               
      }      
    }

    for(i = 0; i < num_ports_to; i++)
    {            
      if (p->dp == sdignorePortTo[i])
      {
        return(1);
      }
    }

    while(sdcurrentHost)
    {
        /*
         * Return 1 if the source addr is in the serverlist, 0 if nothing is
         * found.
         */
        if(dir == DIRECTION_SOURCE)
        {
            if(CheckAddrPort(sdcurrentHost->address, sdcurrentHost->hsp,
                             sdcurrentHost->lsp, p, sdcurrentHost->flags, CHECK_SRC))
            {
                return(1);
            }
        }
        else if(dir == DIRECTION_DST)
        {
            if(CheckAddrPort(sdcurrentHost->address, sdcurrentHost->hsp,
                             sdcurrentHost->lsp, p, sdcurrentHost->flags, INVERSE))
            {
                return(1);
            }
        }
        sdcurrentHost = sdcurrentHost->nextNode;
    }
    return(0);
}


/*
 * Function: AddIpToBlockTree(Packet *p, char bdirection, u_int32_timeout) 
 *
 * Purpose: Add source ip addy's into the splay tree 
 *         
 * Returns: void function
 *
 */
void AddIpToBlockTree(Packet *p, char bdirection, u_int32_t timeout)
{
    if((bdirection == DIRECTION_SOURCE) && (sdIsIgnored(p, DIRECTION_SOURCE)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,"Host %s  matched ignore list, not adding to block tree.\n",inet_ntoa(p->iph->ip_src)););
        return;
    }
    else if((bdirection == DIRECTION_DST) && (sdIsIgnored(p, DIRECTION_DST)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,"Host %s  matched ignore list, not adding to block tree.\n",inet_ntoa(p->iph->ip_dst)););
        return;
    }
    else if((bdirection == DIRECTION_SOURCE) && (sdBlockTreeSearch(p, DIRECTION_SOURCE)))
    {
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,"Host %s already has an entry in block tree, why in the hell is this true we set p->preprocessors and do_detect to 0.\n",inet_ntoa(p->iph->ip_src)););
            return;
    }
    else if((bdirection == DIRECTION_DST) && (sdBlockTreeSearch(p, DIRECTION_DST)))
    {
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,"Host %s already has an entry in block tree, why in the hell is this true we set p->preprocessors and do_detect to 0.\n",inet_ntoa(p->iph->ip_dst)););
            return;
    }

    else
    {
        Attacker *a = NULL;
        MemBucket *mb = NULL;
   
        /* borrow a attacker node from the attacker node pool */
        mb = mempool_alloc(&stickd.AttackerPool);

        if(mb == NULL)
        {
            /* Nuke 5 nodes we are out of memory */
            PruneAttackers(p->pkth->ts.tv_sec, 5, NULL);    
        }

        a = (Attacker *) mb->data;
        a->bucket = mb;

        /* fill in the attacker struct */
        if(bdirection == DIRECTION_SOURCE)
        {
            a->ip = (u_int32_t)p->iph->ip_src.s_addr;
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,"AddIpToBlockTree called going to add ip address %s to block tree\n",inet_ntoa(p->iph->ip_src)););
        }
        else if(bdirection == DIRECTION_DST)
        {
            a->ip = (u_int32_t)p->iph->ip_dst.s_addr;
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,"AddIpToBlockTree called going to add ip address %s to block tree\n",inet_ntoa(p->iph->ip_dst));); 
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                       "not inserting into tree we need src or dst\n"););
        
        }
        
        a->blocktime.tv_sec = p->pkth->ts.tv_sec;
        a->unblocktime.tv_sec = a->blocktime.tv_sec + timeout;
        if(ubi_sptInsert(stickd.attackerRootPtr,
                         (ubi_btNodePtr)a,
                         (ubi_btNodePtr)a, NULL) == ubi_trFALSE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                       "Entry already exists, or something has gone terribly wrong\n"););
            /* We allocated memory let's clean it up */
             mempool_free(&stickd.AttackerPool,a->bucket);
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                       "Insert into block tree was successful\n"););
            DisableDetect(p);
            InlineDrop(p);
        }
    }
}


void SDLog(Packet *p)
{
    char src[STD_BUF];
    char dst[STD_BUF];
    char timestamp[TIMEBUF_SIZE];
    char flagString[9]; 
   
    strlcpy(src, (char *)inet_ntoa(p->iph->ip_src), sizeof(src));
    strlcpy(dst, (char *)inet_ntoa(p->iph->ip_dst), sizeof(dst));
    ts_print((struct timeval *) &p->pkth->ts, timestamp);         

    if(p->tcph)
    {
        CreateTCPFlagString(p, flagString);
        fprintf(stickd.logfile,"Dropped %s TCP %s:%u->%s:%u %s\n", timestamp, src, p->sp, dst, p->dp, flagString);
                
    }
    else if(p->udph)
    {
        fprintf(stickd.logfile,"Dropped %s UDP %s:%u->%s:%u\n", timestamp, src, p->sp, dst, p->dp); 

    }
    else if(p->icmph)      
    {
        fprintf(stickd.logfile, "Dropped %s ICMP %s->%s type: %u code: %u \n", timestamp, src, dst, p->icmph->type, p->icmph->code);

    }             

    fflush(stickd.logfile);
}


/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void StickyDrop(Packet *p, void *context)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(sdPerfStats);


    if (p->iph == NULL)
    {
       PREPROC_PROFILE_END(sdPerfStats);
       return;
    }
    if(sdBlockTreeSearch(p, DIRECTION_SOURCE))
    {
       DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                               "Attacker was found, lets log if specified and drop the packet\n"););
       if(stickd.log)
       {
           /* Log the packet */
           SDLog(p);
       }
           
       /* Disable Detection to save resources and Drop The Packet */

       DisableDetect(p);
       InlineDrop(p);
           
    }
    if(sdBlockTreeSearch(p, DIRECTION_DST))
    {
       DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                               "Attacker was found, lets log if specified and drop the packet\n"););
       if(stickd.log)
       {
           /* Log the packet */
           SDLog(p);
       }

       /* Disable Detection to save resources and Drop The Packet */

       DisableDetect(p);
       InlineDrop(p);

    }
    else
    {
         DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                                 "ip address not found in drop list passing\n"););
    }
    DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,   
                            "Calling Global Prune Check \n"););                         

    PruneAttackers(p->pkth->ts.tv_sec,0,NULL);

    PREPROC_PROFILE_END(sdPerfStats);
}


static int IpAddressCompareFunction(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{            
    Attacker *A = (Attacker *) NodePtr;     
    Attacker *B = (Attacker *) ItemPtr;

    if(A->ip < B->ip)
    {               
        return 1;   
    }         
    else if(A->ip > B->ip)
    {
        return -1;
    }         

    return 0;
}


static void DeleteAttacker(Attacker *a)
{               
    Attacker *olda;

    DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP, "Deleteing Attacker %p\n", a);
               DebugMessage(DEBUG_STICKYDROP,
                            "a->ip: %X\n", a->ip);
               DebugMessage(DEBUG_STICKYDROP,
                            "a->blocktime: %u\n", a->blocktime.tv_sec);
               DebugMessage(DEBUG_STICKYDROP,
                            "a->unblocktime: %u\n", a->unblocktime.tv_sec);

               );


    olda = (Attacker *) ubi_sptRemove(stickd.attackerRootPtr,
                                          (ubi_btNodePtr) a);

    mempool_free(&stickd.AttackerPool,a->bucket);
}    


static int PruneAttackers(u_int32_t now, int tokill, Attacker *saveme)
{
    Attacker *idx;
    u_int32_t pruned = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                            "PruneAttackers called now: "
                            " %u tokill: %d: saveme: %p, count: %u\n",
                            now, tokill, saveme,
                            ubi_trCount(stickd.attackerRootPtr)););

    if(ubi_trCount(stickd.attackerRootPtr) == 0)
    {
        return 0;
    }

    if(tokill == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,  
                                "Running Through Global Prune Check Loop\n"););

        idx = (Attacker *) ubi_btFirst((ubi_btNodePtr)stickd.attackerRootPtr->root);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            if(idx == saveme)
            {
                idx = (Attacker *) ubi_btNext((ubi_btNodePtr)idx);
                continue;
            }

            if((idx->unblocktime.tv_sec) <  now)
            {
                Attacker *savidx = idx;

                if(ubi_trCount(stickd.attackerRootPtr) > 1)
                {
                    idx = (Attacker *) ubi_btNext((ubi_btNodePtr)idx);
                    DEBUG_WRAP(DebugMessage(DEBUG_STICKYDROP,
                                            "pruning stale sticky-drop entry\n"););
                    DeleteAttacker(savidx);
                    pruned++;
                }
                else
                {
                    DeleteAttacker(savidx); 
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                if(idx != NULL && ubi_trCount(stickd.attackerRootPtr) > 1)
                {
                    idx = (Attacker *) ubi_btNext((ubi_btNodePtr)idx);
                }
                else
                {
                    return pruned;
                }
            }
        } while(idx != NULL);

        return pruned;
    }
    else
    {
        while(tokill-- &&  ubi_trCount(stickd.attackerRootPtr) > 0) 
        {
            idx = (Attacker *) ubi_btLeafNode((ubi_btNodePtr)stickd.attackerRootPtr);
            DeleteAttacker(idx);
            return 0;
        }
    }
       return 0;
}


int SppStickydIsRunning(void)
{                
    return s_stickyd_running;
}     


/* 
 * Function: PreprocCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void PreprocCleanExitFunction(int signal, void *data)
{
}


/* 
 * Function: PreprocRestartFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is restarting on a SIGHUP,
 *          if there's any initialization or cleanup that needs to happen
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void PreprocRestartFunction(int signal, void *foo)
{
}


#endif /* GIDS */
