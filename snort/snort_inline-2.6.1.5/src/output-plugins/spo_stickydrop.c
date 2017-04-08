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

#include <sys/types.h>

#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "plugin_enum.h"
#include "detection-plugins/sp_stickydrop.h"
#include "preprocessors/spp_stickydrop.h"
#include "snort.h"
#include "util.h"

/* list of function prototypes for this output plugin */
void AlertStickyDInit(u_char *);
void AlertStickyD(Packet *, char *, void *, Event *);
void AlertStickyDCleanExitFunc(int, void *);
void AlertStickyDRestartFunc(int, void *);

extern OptTreeNode *otn_tmp;
extern PV pv;

static int stickyd_out_running = 0; 

void AlertStickyDSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_StickyD", NT_OUTPUT_ALERT, AlertStickyDInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output plugin: StickyD is setup...\n"););
}


void AlertStickyDInit(u_char *args)
{
    if(!SppStickydIsRunning())
    {
        FatalError("dude, you can't have a stickydrop output-plugin without the stickydrop preproc\n");
    }
    
    stickyd_out_running = 1;
 
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: StickyD Initialized\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertStickyD, NT_OUTPUT_ALERT, NULL);
    AddFuncToCleanExitList(AlertStickyDCleanExitFunc, NULL);
    AddFuncToRestartList(AlertStickyDRestartFunc, NULL);
}



void AlertStickyD(Packet *p, char *msg, void *arg, Event *event)
{
    StickyDSp *stickydsp_o;
    stickydsp_o=NULL;


    if(otn_tmp==NULL)
    {
        return;
    }
    if(p == NULL)
    {
        return;
    }

    if(otn_tmp->ds_list[PLUGIN_STICKYDSP])
    { 
       stickydsp_o=otn_tmp->ds_list[PLUGIN_STICKYDSP];
     
       if(stickydsp_o) 
       {
          printf("adding packet to block tree because we have options");
          AddIpToBlockTree(p, stickydsp_o->stickyd_direction, stickydsp_o->stickyd_timeout);
       }
    }
    else
    {
       return;
    }
}

int StickyDOutputInitRun(void)
{
    return stickyd_out_running;
}

void AlertStickyDCleanExitFunc(int signal, void *arg)
{
    return;
}

void AlertStickyDRestartFunc(int signal, void *arg)
{
    return;
}
#endif /* GIDS */
