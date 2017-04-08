/* $Id: ClamAV-2.3.3-1.diff,v 1.1.1.1 2005/05/06 21:19:36 jonkman Exp $ */  
/* Snort Preprocessor Plugin Header File Template */

/* This file gets included in plugbase.h when it is integrated into the rest
 * of the program.
 */
#ifndef __SPP_CLAMAV_H__
#define __SPP_CLAMAV_H__

#ifdef CLAMAV
/*
 * list of function prototypes to export for this preprocessor
 */
void SetupClamAV();

#endif /* CLAMAV */

#endif  /* __SPP_CLAMAV_H__ */

