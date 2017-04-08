/* $Id: spp_template.h,v 1.4 2004/02/13 16:19:03 roesch Exp $ */
/* Snort Preprocessor Plugin Header File Template */

/* This file gets included in plugbase.h when it is integrated into the rest 
 * of the program.  
 */

#ifndef __SPP_BAIT_AND_SWITCH_H__
#define __SPP_BAIT_AND_SWITCH_H__


/* we only want SD in inline mode */
#ifdef GIDS
#ifndef IPFW

void SetupBaitAndSwitch();
void AddIpToRerouteTree(Packet *, char, uint32_t, uint32_t);
int BaitAndSwitchIsRunning(void);
char restorecmd[255];
char savecmd[255];
#endif /* IPFW */
#endif /* GIDS */

#endif  /* __SPP_BAIT_AND_SWITCH_H__ */
