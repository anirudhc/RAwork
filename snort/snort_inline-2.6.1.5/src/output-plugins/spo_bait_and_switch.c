/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
#ifdef GIDS
#ifndef IPFW

#include <sys/types.h>

#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "plugin_enum.h"
#include "detection-plugins/sp_bait_and_switch.h"
#include "preprocessors/spp_bait_and_switch.h"
#include "snort.h"
#include "util.h"

/* list of function prototypes for this output plugin */
void AlertBandSInit(u_char *);
void AlertBandS(Packet *, char *, void *, Event *);
void AlertBandSCleanExitFunc(int, void *);
void AlertBandSRestartFunc(int, void *);

extern OptTreeNode *otn_tmp;
extern PV pv;

static int bands_out_running = 0; 

void AlertBandSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_BandS", NT_OUTPUT_ALERT, AlertBandSInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output plugin: BandS is setup...\n"););
}


void AlertBandSInit(u_char *args)
{
    if(!BaitAndSwitchIsRunning())
    {
        FatalError("dude, you can't have a bait-and-switch output-plugin without the bait-and-switch preproc\n");
    }
    
    bands_out_running = 1;
 
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: BandS Initialized\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertBandS, NT_OUTPUT_ALERT, NULL);
    AddFuncToCleanExitList(AlertBandSCleanExitFunc, NULL);
    AddFuncToRestartList(AlertBandSRestartFunc, NULL);
}



void AlertBandS(Packet *p, char *msg, void *arg, Event *event)
{
    BandSp *bandsp_o;
    bandsp_o=NULL;


    if(otn_tmp==NULL)
    {
        return;
    }
    if(p == NULL)
    {
        return;
    }

    if(otn_tmp->ds_list[PLUGIN_BANDSP])
    { 
       bandsp_o=otn_tmp->ds_list[PLUGIN_BANDSP];
     
       if(bandsp_o) 
       {
          printf("adding packet to reroute tree because we have bands options");
          AddIpToRerouteTree(p, bandsp_o->bands_direction, bandsp_o->bands_timeout, bandsp_o->hpotaddr);
       }
    }
    else
    {
       return;
    }
}

int BaitAndSwitchOutputInitRun(void)
{
    return bands_out_running;
}

void AlertBandSCleanExitFunc(int signal, void *arg)
{
    return;
}

void AlertBandSRestartFunc(int signal, void *arg)
{
    return;
}
#endif /* IPFW */
#endif /* GIDS */
