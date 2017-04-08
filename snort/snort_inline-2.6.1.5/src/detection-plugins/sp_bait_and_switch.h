/* $Id: sp_template.h,v 1.4 2004/02/13 16:19:03 roesch Exp $ */
/* Snort Detection Plugin Header File Template */

/* 
 * This file gets included in plugbase.h when it is integrated into the rest 
 * of the program.  
 *
 * Export any functions or data structs you feel necessary.
 */

#ifndef __SP_BAIT_AND_SWITCH_H__
#define __SP_BAIT_AND_SWITCH_H__

#ifdef GIDS
#ifndef IPFW

void SetupBandSp();

typedef struct _BandSp
{
    int bands_timeout;
    char bands_direction;
    u_int32_t hpotaddr;

} BandSp;

#endif /* IPFW */
#endif /* GIDS */

#endif  /* __SP_BAIT_AND_SWITCH_H__ */
