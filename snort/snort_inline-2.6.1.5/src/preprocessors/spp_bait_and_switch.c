/* $Id: spp_template.c,v 1.5 2004/02/13 16:19:03 roesch Exp $ */
/* Snort Preprocessor Plugin Source File Template */

/* spp_bait_and_switch 
 * 
 * Purpose:
 *
 * Based on Sticky-Drop the original Bait-and-switch project, and Snortsam, we want to really fuck with our attackers.  
 *
 * Arguments:
 *   
 *
 *
 */


/* bait_and_switch is for inline */
#ifdef GIDS
#ifndef IPFW

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>
#include <string.h>
#include <stdio.h>
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

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#include "spp_bait_and_switch.h"
#include "inline.h"
#include "profiler.h"

#define MAX_PORTS		64
#define MEM_CHUNK		32
#define DIRECTION_SOURCE	0
#define DIRECTION_DST		1

/* Data Used for Bait-and-Switch */
typedef struct _BandS
{
    ubi_trRoot attackerRoot;  /* this tree is for the reroute info */
    ubi_trRootPtr attackerRootPtr;
    MemPool AttackerPool;
    u_int32_t max_reroute_entries;
    char log;
    FILE *logfile;
    char *logpath;
    char iptpath[255];
    char iptcmd[255];
    char *insertmode;   
} BandS;

BandS bands;


typedef struct _Attacker
{
    ubi_trNode Node;             /* for the splay tree */
    MemBucket *bucket;
    u_int32_t attackerip;
    u_int32_t honeypotip;
    u_int32_t attackedip;
    u_int32_t timeout;
    struct timeval ruleaddtime;
    struct timeval ruledeletetime;
    char iptdnatcmd[255];
    char iptsnatcmd[255];
    char iptundnatcmd[255];
    char iptunsnatcmd[255];
} Attacker;

Attacker attacker;

typedef struct _bashostNode
{
    IpAddrSet *address;
    u_short hsp;         /* hi src port */
    u_short lsp;         /* lo src port */
    u_int32_t flags;     /* control flags */
    struct _bashostNode *nextNode;

} basHostNode;

basHostNode *basignoreList; /* for ignore-hosts */
int num_ports_from;
int num_ports_to;
u_int32_t *basignorePortFrom;
u_int32_t *basignorePortTo;

static void BaitandSwitchInit(u_char *);
static void ParseBaitandSwitchArgs(char *);
void BaitAndSwitch(Packet *, void *);
void BASLog(Packet *);

static int IpAddressCompareFunction(ubi_trItemPtr, ubi_trNodePtr);
static int PruneAttackers(u_int32_t now, int tokill, Attacker *saveme);
static void BaitAndSwitchCleanExitFunction(int, void *);
static void BaitAndSwitchRestartFunction(int, void *);

/* For ignore hosts */
void basInitIgnoreHosts(u_char *);
IpAddrSet* basIgnoreAllocAddrNode(basHostNode *);
void basScanParseIp(char *, basHostNode *);

/* For ignore ports */
void basInitIgnoreFrom(u_char *);
void basInitIgnoreTo(u_char *);
void basInitIgnorePorts(u_char *, u_int32_t **, int *);
u_int32_t basScanParsePort(char *);

int basIsIgnored(Packet *, char);
int basAttackerSearch(Packet *, char);

static int s_bas_running = 0;

#ifdef PERF_PROFILING
PreprocStats bandsPerfStats;
#endif 

/*
 * Function: ()
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
void SetupBaitAndSwitch()
{
    /* 
     * link the preprocessor keyword to the init function in 
     * the preproc list 
     */
    RegisterPreprocessor("bait-and-switch", BaitandSwitchInit);
    RegisterPreprocessor("bait-and-switch-ignorehosts", basInitIgnoreHosts);
    RegisterPreprocessor("bait-and-switch-ignoreports-from", basInitIgnoreFrom);
    RegisterPreprocessor("bait-and-switch-ignoreports-to", basInitIgnoreTo);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: BaitAndSwitch is setup...\n"););
}


/*
 * Function: BaitAndSwitchInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void BaitandSwitchInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: BaitAndSwitch Initialized\n"););

    memset(&bands, 0, sizeof(BandS));
    ParseBaitandSwitchArgs(args);
    bands.attackerRootPtr = &bands.attackerRoot;

    ubi_trInitTree(bands.attackerRootPtr, IpAddressCompareFunction, 0);
    if(mempool_init(&bands.AttackerPool , bands.max_reroute_entries, sizeof(Attacker)))
    {
      FatalError("ERROR: Could not alloc memory for baitandswitch entries\n");
    }
    else if(!InlineMode()) 
    {
      FatalError("ERROR: We have to be in InlineMode() to use baitandswitch\n"); 
    }

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("Bait-And-Switch", &bandsPerfStats, 0, &totalPerfStats);
#endif
    
    s_bas_running = 1;
    if (system(savecmd) != 0) 
    {
        FatalError("ERROR: failed to save iptables state before Bait-And-Switch bailing\n");
    }

    AddFuncToPreprocList(BaitAndSwitch, PRIORITY_NETWORK, PP_BAITANDSWITCH);
    AddFuncToPreprocCleanExitList(BaitAndSwitchCleanExitFunction, NULL, PRIORITY_FIRST, PP_BAITANDSWITCH);
    AddFuncToPreprocRestartList(BaitAndSwitchRestartFunction, NULL, PRIORITY_FIRST, PP_BAITANDSWITCH);

    /* fire up the bands output plugin */
    ActivateOutputPlugin("alert_BandS",NULL);
}


/*
 * Function: ParseBaitAndSwitchArgs(char *)
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
static void ParseBaitandSwitchArgs(char *args)
{
    int num_toks, s_toks;
    char **toks = NULL;
    char **stoks;
    char **iptdirtoks;
    int num_iptdirtoks = 0;
    int i;
    char* index;
    char logpath[STD_BUF], tmp[STD_BUF];
    bands.insertmode="A";
    /* setup the defaults */
    strlcpy(logpath, pv.log_dir, STD_BUF);
    strlcpy(tmp, "/bands.log", STD_BUF);
    strlcat(logpath, tmp, STD_BUF);
 
    strlcpy(bands.iptpath,"/sbin",STD_BUF);
   
    if(snprintf(bands.iptcmd,sizeof(bands.iptcmd) -1,"%s/iptables",bands.iptpath) >= sizeof(bands.iptcmd))
    {
        FatalError("The iptcmd supplied is too long\n");
    }
    else if(snprintf(savecmd,sizeof(savecmd) -1,"%s/iptables-save > %s/iptables-rules",bands.iptpath,pv.log_dir) >= sizeof(savecmd))
    {
        FatalError("The iptsavecmd is too long\n");
    }
    else if(snprintf(restorecmd,sizeof(restorecmd) -1,"%s/iptables-restore < %s/iptables-rules",bands.iptpath,pv.log_dir) >= sizeof(restorecmd))
    {
        FatalError("The iptrestorecmd is too long\n");
    }
    else
    {
        LogMessage("default iptcmd is %s\n",bands.iptcmd);
        LogMessage("default iptsave is %s\n",savecmd);
        LogMessage("default iptrestore is %s\n",restorecmd);
    } 
    bands.max_reroute_entries = 100;
    bands.log = 0;
    if (args)
    {

        toks = mSplit(args, ",", 7, &num_toks, 0);

        i=0;

        while (i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 5, &s_toks, 0);
            if(!strcasecmp(stoks[0], "max_entries"))
            {
                if(isdigit((int)(stoks[1][0])))
                {
                    /* number of tgtnodes */
                    bands.max_reroute_entries = atoi(stoks[1]);
                    i++;
                }
                else
                {
                    FatalError("Bad BaitAndSwitch Max Entries Arg",file_name,file_line);
                }
    
            }
            else if(!strcasecmp(stoks[0], "log"))
            {
                bands.log = 1;
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
            }
            else if(!strcasecmp(stoks[0],"insert_before"))
            {
                bands.insertmode = "I";
                i++;
            }           
            else if(!strncasecmp(index, "iptpath", 7))
            {
                /* get the argument for the option */
                iptdirtoks = mSplit(index, " ", 1, &num_iptdirtoks, 0);

                /* copy it to the clamcnf */
                if(strlcpy(bands.iptpath, iptdirtoks[1], sizeof(bands.iptpath)) >= sizeof(bands.iptpath))
                {
                    FatalError("The iptpath supplied in the config is too long\n");
                }
                else if(snprintf(bands.iptcmd,sizeof(bands.iptcmd) -1,"%s/iptables",bands.iptpath) >= sizeof(bands.iptcmd))
                {
                   FatalError("The iptcmd supplied is too long\n");
                }
                else if(snprintf(savecmd,sizeof(savecmd) -1,"%s/iptables-save > %s/iptables-rules",bands.iptpath,pv.log_dir) >= sizeof(savecmd))
                {
                   FatalError("The iptsavecmd is too long\n");
                }
                else if(snprintf(restorecmd,sizeof(restorecmd) -1,"%s/iptables-restore < %s/iptables-rules",bands.iptpath,pv.log_dir) >= sizeof(restorecmd))
                {
                   FatalError("The iptrestorecmd is too long\n");
                }
                else
                {
                   mSplitFree(&iptdirtoks, num_iptdirtoks);
                   LogMessage("iptcmd command is now %s\n",bands.iptcmd);
                   LogMessage("iptsave command is now %s\n",savecmd);
                   LogMessage("iptrestore command is now %s\n",restorecmd);
                   i++;
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
    if(bands.log)
    {
        bands.logfile = fopen(logpath, "a+");

        if(bands.logfile == NULL)
        {
            FatalError("Can't open logfile: %s", bands.logpath);
        }
    }
}
void basInitIgnoreHosts(u_char *hosts)
{
    char **toks;
    int num_toks;
    int num_hosts = 0;
    basHostNode *bascurrentHost;
    /*int i;*/

    bascurrentHost = NULL;
    basignoreList = NULL;

    if(hosts == NULL)
    {
        ErrorMessage(" ERROR: %s(%d)=> No arguments to "
                     "bait-and-switch-ignorehosts, ignoring.\n",
                     file_name, file_line);
        return;
    }

    toks = mSplit(hosts, " ", 127, &num_toks, '\\');

    for(num_hosts = 0; num_hosts < num_toks; num_hosts++)
    {
        if((bascurrentHost = (basHostNode *) calloc(1, sizeof(basHostNode))) == NULL)
        {
            FatalError("[!] ERROR: Unable to allocate space for "
                       "bait-and-switch IgnoreHost");
        }
        bascurrentHost->address = NULL; /* be paranoid */
        bascurrentHost->nextNode = basignoreList;
        basignoreList = bascurrentHost;


        basScanParseIp(toks[num_hosts], bascurrentHost);
    }

    mSplitFree(&toks, num_toks);
}


IpAddrSet* basIgnoreAllocAddrNode(basHostNode *host)
{
    IpAddrSet *idx;

    if((idx = (IpAddrSet *) calloc(1, sizeof(IpAddrSet))) == NULL)
      {
        FatalError("[!] ERROR: Unable to allocate space for "
                       "BaitAndSwitch IP addr\n");
      }

    idx->next = host->address;
    host->address = idx;

    return idx;
}


void basScanParseIp(char *addr, basHostNode *host)
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
                     "bait-and-switch-ignorehosts directive, igoring.\n", file_name,
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
                     "bait-and-switch-ignorehosts \"%s\"\n",
                     file_name, file_line, tmp);
        }
        toks = mSplit(tmp+1, ",", 128, &num_toks, 0);

        for(i = 0; i < num_toks; i++)
        {
            tmp_addr = basIgnoreAllocAddrNode(host);

            ParseIP(toks[i], tmp_addr);
        }

        mSplitFree(&toks, num_toks);
    }
    else
    {
        if (ports) *ports = '\x0'; /* null out the at */

        tmp_addr = basIgnoreAllocAddrNode(host);
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


void basInitIgnoreFrom(u_char *args)
{
  basInitIgnorePorts(args, &basignorePortFrom, &num_ports_from);
}


void basInitIgnoreTo(u_char *args)
{
  basInitIgnorePorts(args, &basignorePortTo, &num_ports_to);
}


void basInitIgnorePorts(u_char *list, u_int32_t **ports, int *num)
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
                     "bait-and-switch-ignoreports, ignoring.\n",
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
                     "bait-and-switch-ignoreports");
        }
        if (*ports != NULL)
        {
          memcpy(pool, *ports, max_ports * sizeof(u_int32_t));
          free(*ports);
        }
        max_ports = new_ports;
        *ports = pool;
      }
      (*ports)[*num] = basScanParsePort(toks[*num]);
    }

    mSplitFree(&toks, num_toks);

}


u_int32_t basScanParsePort(char *port)
{
    char *tmp;

    if(port == NULL)
    {
      FatalError("ERROR %s(%d) => Undefined ports in "
                 "bait-and-switch-ignoreports directive\n",
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
                 "bait-and-switch-ignoreports\n", file_name, file_line);
    }

    return((u_int32_t)atol(tmp));
}

int basAttackerSearch(Packet *p, char direction)
{
    Attacker *searchval;
    Attacker tmp;
    char pattacker[STD_BUF];
    char phoneypot[STD_BUF];

    if(direction == DIRECTION_SOURCE)
    {
        tmp.attackerip = (u_int32_t)p->iph->ip_src.s_addr;
        tmp.honeypotip = (u_int32_t)p->iph->ip_dst.s_addr;
        snprintf(pattacker,sizeof(pattacker) -1,"%s",(char *)inet_ntoa(p->iph->ip_src));
        snprintf(phoneypot,sizeof(phoneypot) -1,"%s",(char *)inet_ntoa(p->iph->ip_dst));

    }
    if(direction == DIRECTION_DST)
    {
        tmp.attackerip = (u_int32_t)p->iph->ip_dst.s_addr;
        tmp.honeypotip = (u_int32_t)p->iph->ip_src.s_addr;
        snprintf(pattacker,sizeof(pattacker) -1,"%s",(char *)inet_ntoa(p->iph->ip_src));    
        snprintf(phoneypot,sizeof(phoneypot) -1,"%s",(char *)inet_ntoa(p->iph->ip_dst));  
    }
    if(ubi_trCount(bands.attackerRootPtr) == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                   "we don't have any entries in the attacker table running through normal snort preprocessors and detection engine\n"););
        return 0;
    }
    
        searchval = (Attacker *) ubi_btFirst((ubi_btNodePtr)bands.attackerRootPtr->root);

        if(searchval == NULL)               
        {
            return 0;
        }

        do
        {


            if((searchval->attackerip == tmp.attackerip) && (searchval->honeypotip == tmp.honeypotip))
            {              

                if(p->pkth->ts.tv_sec >= (searchval->ruledeletetime.tv_sec))         
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                                            "Pruning out Attacker entry %s due to timeout\n",pattacker););

                     PruneAttackers(p->pkth->ts.tv_sec, 1, NULL);

                     return(0);
                }

                else
                {
                     DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                                            "Attacker/Honeypot attacker:%s honeypot:%s pair found in tree\n",pattacker,phoneypot););
                     return(1);
                }
            }
            else if((searchval->attackerip == tmp.attackerip) && (searchval->attackedip == tmp.honeypotip))
            {
           
                /*either this connection is left over from before we added our DNAT/SNAT rules or something is fucked in iptables*/
                DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                                        "assuming stale iptables connection tearing down session attacker:%s attackedip:%s\n",pattacker,phoneypot););
                InlineReject(p);
                return(1);
            }
            else
            {
                if(searchval != NULL && ubi_trCount(bands.attackerRootPtr))
                {
                    searchval = (Attacker *) ubi_btNext((ubi_btNodePtr)searchval);
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                               "attacker not found src %s dst %s\n",pattacker,phoneypot););
                    return (0);
                }
            }
        } while(searchval != NULL);

        return (0);
}
int basIsIgnored(Packet *p, char dir)
{                 
    basHostNode *bascurrentHost = basignoreList;
    int i;                

    for(i = 0; i < num_ports_from; i++)
    {
      if (p->sp == basignorePortFrom[i])   
      {
        return(1);               
      }      
    }

    for(i = 0; i < num_ports_to; i++)
    {            
      if (p->dp == basignorePortTo[i])
      {
        return(1);
      }
    }

    while(bascurrentHost)
    {
        /*
         * Return 1 if the source addr is in the serverlist, 0 if nothing is
         * found.
         */
        if(dir == DIRECTION_SOURCE)
        {
            if(CheckAddrPort(bascurrentHost->address, bascurrentHost->hsp,
                             bascurrentHost->lsp, p, bascurrentHost->flags, CHECK_SRC))
            {
                return(1);
            }
        }
        else if(dir == DIRECTION_DST)
        {
            if(CheckAddrPort(bascurrentHost->address, bascurrentHost->hsp,
                             bascurrentHost->lsp, p, bascurrentHost->flags, INVERSE))
            {
                return(1);
            }
        }
        bascurrentHost = bascurrentHost->nextNode;
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
void AddIpToRerouteTree(Packet *p, char bdirection, u_int32_t timeout, u_int32_t hpotip)
{
    
    if((bdirection == DIRECTION_SOURCE) && (basIsIgnored(p, DIRECTION_SOURCE)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,"Host %s  matched ignore list, not adding to reroute tree.\n",inet_ntoa(p->iph->ip_src)););
        return;
    }
    else if((bdirection == DIRECTION_DST) && (basIsIgnored(p, DIRECTION_DST)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,"Host %s  matched ignore list, not adding to reroute tree.\n",inet_ntoa(p->iph->ip_dst)););
        return;
    }
    
    else
    {
        Attacker *a = NULL;
        MemBucket *mb = NULL;
        char fattacker[STD_BUF];
        char fattacked[STD_BUF];
        char fhoneypot[STD_BUF];
        struct in_addr hpot; 
        /* borrow a attacker node from the attacker node pool */
        mb = mempool_alloc(&bands.AttackerPool);

        if(mb == NULL)
        {
            /* Nuke 5 nodes we are out of memory */
            PruneAttackers(p->pkth->ts.tv_sec, 5, NULL);    
        }
        a = (Attacker *) mb->data;
        a->bucket = mb;
        hpot.s_addr=(ulong)hpotip; 
        /* fill in the attacker struct */
        if(bdirection == DIRECTION_SOURCE)
        {
            a->attackerip = (u_int32_t)p->iph->ip_src.s_addr;
            a->attackedip = (u_int32_t)p->iph->ip_dst.s_addr;
            a->honeypotip = (u_int32_t)hpot.s_addr;
            snprintf(fattacker,sizeof(fattacker) -1,"%s",(char *)inet_ntoa(p->iph->ip_src));
            snprintf(fattacked,sizeof(fattacked) -1,"%s",(char *)inet_ntoa(p->iph->ip_dst));
            snprintf(fhoneypot,sizeof(fhoneypot) -1,"%s",(char *)inet_ntoa(hpot));
        }
        else if(bdirection == DIRECTION_DST)
        {
            a->attackerip = (u_int32_t)p->iph->ip_dst.s_addr;
            a->attackedip = (u_int32_t)p->iph->ip_src.s_addr;
            a->honeypotip = (u_int32_t)hpot.s_addr;
            snprintf(fattacker,sizeof(fattacker) -1,"%s",(char *)inet_ntoa(p->iph->ip_dst));
            snprintf(fattacked,sizeof(fattacked) -1,"%s",(char *)inet_ntoa(p->iph->ip_src));
            snprintf(fhoneypot,sizeof(fhoneypot) -1,"%s",(char *)inet_ntoa(hpot));
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                       "not inserting into tree we need src or dst\n"););
            mempool_free(&bands.AttackerPool,a->bucket);
            return;

        }

  
        if(a->attackedip == a->honeypotip)
        {  
            DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH, 
                       "attackedip %s is equal to the honeypot ip address %s\n",fattacked,fhoneypot););
           mempool_free(&bands.AttackerPool,a->bucket);
           return;
        }
            DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                       "attacker %s attacked %s hpot %s\n",fattacker,fattacked,fhoneypot););

        if(snprintf(a->iptdnatcmd,sizeof(a->iptdnatcmd) -1,"%s -t nat -%s PREROUTING -s %s -d %s -j DNAT --to-destination %s",bands.iptcmd,bands.insertmode,fattacker,fattacked,fhoneypot) >= sizeof(a->iptdnatcmd))
        {
           DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                      "could not add PREROUTING -A rule it was to long\n"););
           return;
        }
        if(snprintf(a->iptsnatcmd,sizeof(a->iptsnatcmd) -1,"%s -t nat -%s POSTROUTING -s %s -d %s -j SNAT --to-source %s",bands.iptcmd,bands.insertmode,fhoneypot, fattacker, fattacked) >= sizeof(a->iptsnatcmd))
        {
           DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                      "could not add POSTROUTING -A rule it was to long\n"););
           return;
        }
        if(snprintf(a->iptundnatcmd,sizeof(a->iptundnatcmd) -1,"%s -t nat -D PREROUTING -s %s -d %s -j DNAT --to-destination %s",bands.iptcmd,fattacker, fattacked, fhoneypot) >= sizeof(a->iptundnatcmd))
        {
           DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                      "could not add PREROUTING -D rule it was to long\n"););
           return;
        }
        if(snprintf(a->iptunsnatcmd,sizeof(a->iptunsnatcmd) -1,"%s -t nat -D POSTROUTING -s %s -d %s -j SNAT --to-source %s",bands.iptcmd,fhoneypot, fattacker, fattacked) >= sizeof(a->iptunsnatcmd))
        {
           DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                      "could not add POSTROUTING -D rule it was to long\n"););
           return;
        }
 
        a->ruleaddtime.tv_sec = p->pkth->ts.tv_sec;
        a->ruledeletetime.tv_sec = a->ruleaddtime.tv_sec + timeout;
        if(ubi_sptInsert(bands.attackerRootPtr,
                         (ubi_btNodePtr)a,
                         (ubi_btNodePtr)a, NULL) == ubi_trFALSE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                       "Entry already exists, or something has gone terribly wrong\n"););
            /* We allocated memory let's clean it up */
             mempool_free(&bands.AttackerPool,a->bucket);
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                       "Insert into reroute tree was successful\n"););
            if(system(a->iptdnatcmd) !=0)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                          "failed to add iptables DNAT rule"););
            }
            else
            {
               DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                          "added iptables DNAT rule\n"););
               if(bands.log)
               {
                   fprintf(bands.logfile,"DNATing all traffic from attackerip: %s bound for ip address: %s to honeypotip of %s\n",fattacker, fattacked, fhoneypot);
               }    
            }

            if(system(a->iptsnatcmd) != 0)
            {
               DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                          "failed to add iptables SNAT rule\n"););
            }
            else
            {
               DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                          "added iptables SNAT rule\n"););
                if(bands.log)
                {
                    fprintf(bands.logfile,"SNATing all traffic from honeypot ip: %s bound for attackerip: %s to source of attacked ip: %s\n",fhoneypot, fattacker, fattacked);
                }
            }
            DisableDetect(p);
            InlineReject(p);
        }
    }
}


void BASLog(Packet *p)
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
        fprintf(bands.logfile,"Rerouted Packet %s TCP %s:%u->%s:%u %s\n", timestamp, src, p->sp, dst, p->dp, flagString);
                
    }
    else if(p->udph)
    {
        fprintf(bands.logfile,"Rerouted Packet %s UDP %s:%u->%s:%u\n", timestamp, src, p->sp, dst, p->dp); 

    }
    else if(p->icmph)      
    {
        fprintf(bands.logfile, "Rerouted Packet %s ICMP %s->%s type: %u code: %u \n", timestamp, src, dst, p->icmph->type, p->icmph->code);

    }             

    fflush(bands.logfile);
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
void BaitAndSwitch(Packet *p, void *context)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(bandsPerfStats);

    if (p->iph == NULL)
    {
       return;
    }

    if(basAttackerSearch(p, DIRECTION_SOURCE))
    {
       DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                               "Attacker was found, lets log if specified and set do_detect = 0 and p->processors =0; the packet\n"););
       if(bands.log)
       {
           /* Log the packet */
           BASLog(p);
       }
           
       /* Disable Detection to save resources and Drop The Packet */
       
       DisableDetect(p);
           
    }
    if(basAttackerSearch(p, DIRECTION_DST))
    {
       DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                               "Attacker was found, lets log if specified and set do_detect = 0 and p->processors =0; the packet\n"););
       if(bands.log)
       {
           /* Log the packet */
           BASLog(p);
       }

       /* Disable Detection to save resources and Drop The Packet */
       DisableDetect(p);

    }
    else
    {
         DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                                 "ip address not found in drop list passing\n"););
    }
    DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,   
                            "Calling Global Prune Check \n"););                         

    PruneAttackers(p->pkth->ts.tv_sec,0,NULL);
    PREPROC_PROFILE_END(bandsPerfStats);
}


static int IpAddressCompareFunction(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{            
    Attacker *A = (Attacker *) NodePtr;     
    Attacker *B = (Attacker *) ItemPtr;

    if(A->attackerip < B->attackerip)
    {               
        return 1;   
    }         
    else if(A->attackerip > B->attackerip)
    {
        return -1;
    }         
    if(A->attackedip < B->attackedip)
    {
        return 1;
    }
    else if(A->attackedip > B->attackedip) 
    {
        return -1;
    }
    if(A->honeypotip < B->honeypotip)
    {
        return 1;
    }
    else if(A->honeypotip > B->honeypotip)
    {
        return -1;
    }                   
    return 0;
}


static void DeleteAttacker(Attacker *a)
{               
    Attacker *olda;

    DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH, "Deleteing Attacker %p\n", a);
               DebugMessage(DEBUG_BAITANDSWITCH,
                            "a->ip: %X\n", a->attackerip);
               DebugMessage(DEBUG_BAITANDSWITCH,
                            "a->ruleaddtime: %u\n", a->ruleaddtime.tv_sec);
               DebugMessage(DEBUG_BAITANDSWITCH,
                            "a->ruledeletetime: %u\n", a->ruledeletetime.tv_sec);

               );

   if(system(a->iptundnatcmd) !=0)
   {
       DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                  "failed to delete iptables DNAT rule\n"););
   }
   else
   {
       DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH, 
                  "deleted iptables DNAT rule\n"););
   }

   if(system(a->iptunsnatcmd) != 0)
   {
       DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH, 
                  "failed to delete iptables SNAT rule\n"););
   }
   else
   {
       DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH, 
                  "deleted iptables SNAT rule\n"););
   }
        
    olda = (Attacker *) ubi_sptRemove(bands.attackerRootPtr,
                                          (ubi_btNodePtr) a);

    mempool_free(&bands.AttackerPool,a->bucket);
}    


static int PruneAttackers(u_int32_t now, int tokill, Attacker *saveme)
{
    Attacker *idx;
    u_int32_t pruned = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                            "PruneAttackers called now: "
                            " %u tokill: %d: saveme: %p, count: %u\n",
                            now, tokill, saveme,
                            ubi_trCount(bands.attackerRootPtr)););

    if(ubi_trCount(bands.attackerRootPtr) == 0)
    {
        return 0;
    }

    if(tokill == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,  
                                "Running Through Global Prune Check Loop\n"););

        idx = (Attacker *) ubi_btFirst((ubi_btNodePtr)bands.attackerRootPtr->root);

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

            if((idx->ruledeletetime.tv_sec) <  now)
            {
                Attacker *savidx = idx;

                if(ubi_trCount(bands.attackerRootPtr) > 1)
                {
                    idx = (Attacker *) ubi_btNext((ubi_btNodePtr)idx);
                    DEBUG_WRAP(DebugMessage(DEBUG_BAITANDSWITCH,
                                            "pruning stale BAITANDSWITCH entry\n"););
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
                if(idx != NULL && ubi_trCount(bands.attackerRootPtr) > 1)
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
        while(tokill-- &&  ubi_trCount(bands.attackerRootPtr) > 0) 
        {
            idx = (Attacker *) ubi_btLeafNode((ubi_btNodePtr)bands.attackerRootPtr);
            DeleteAttacker(idx);
            return 0;
        }
    }
       return 0;
}


int BaitAndSwitchIsRunning(void)
{                
    return s_bas_running;
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
static void BaitAndSwitchCleanExitFunction(int signal, void *data)
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
static void BaitAndSwitchRestartFunction(int signal, void *foo)
{

}

#endif /* IPFW */
#endif /* GIDS */

