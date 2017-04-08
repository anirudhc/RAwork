/* $Id: spp_template.h,v 1.4 2004/02/13 16:19:03 roesch Exp $ */
/* Snort Preprocessor Plugin Header File Template */

/* This file gets included in plugbase.h when it is integrated into the rest 
 * of the program.
 */

#ifndef __SPP_STICKY_H__
#define __SPP_STICKY_H__


/* we only want SD in inline mode */
#ifdef GIDS


/* 
 * list of function prototypes to export for this preprocessor 
 */
typedef struct _SDtimeout
{
   int sfportscan;
   int clamav;
} SDtimeout;


void SetupStickyDrop();
void AddIpToBlockTree(Packet *, char, uint32_t);
int SppStickydIsRunning(void);

#endif /* GIDS */

#endif  /* __SPP_STICKY_H__ */
