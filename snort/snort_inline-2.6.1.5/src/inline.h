// $Id$
#ifndef __INLINE_H__
#define __INLINE_H__

#ifdef GIDS

#ifndef IPFW
#ifdef NFNETLINKQ
//#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libipq.h>
#include <net/if.h>
#else
#include <libipq.h>
#endif /* NFNETLINKQ */
#include <linux/netfilter.h>
#else /* IPFW */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <errno.h>
#endif /* IPFW */

#include "snort.h"
int InlineMode();
int InlineModeSetPrivsAllowed();
int InlineDrop(Packet *p);  /* call to drop current packet */
int InlineDropPacketOnly(Packet *p);  /* call to drop current packet */
int InlineWasPacketDropped();
int opdsize;  /* original packet p->dsize for resets */

typedef struct _inline_vals
{
    int drop;
    int rejectsrc;
    int rejectdst;
    int reinject;
    int replace;
    int proto;
} IV;



#ifdef NFNETLINKQ
u_int16_t nfqueue_num;
struct nfnl_handle *nh;
#else
#ifndef IPFW
struct ipq_handle *ipqh;
#else
int divert_socket;
#endif /* IPFW */
#endif /* NFNETLINKQ */

IV iv;

int InitInline();
void InitInlinePostConfig(void);
void RejectFuRestart();
int InlineReject(Packet *); /* call to reject src in current packet for compat */
int InlineRejectBoth(Packet *); /* call to reject current packet in both directions */
int InlineRejectSrc(Packet *); /* call to reject src in current packet */
int InlineRejectDst(Packet *); /* call to reject dst in current packet */
#ifdef IPFW
int InlineReinject(Packet *); /* call to reinject current packet */
#endif /* IPFW */
int InlineAccept();
int InlineReplace();

#ifdef NFNETLINKQ
void NfnetlinkQLoop();
#else

#ifndef IPFW
void IpqLoop();
#else
void IpfwLoop();
#endif /* IPFW */
#endif /* NFNETLINKQ */
#endif /* GIDS */

#endif /* __INLINE_H__ */
