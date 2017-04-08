/* $Id$ */
/*
 ** Portions Copyright (C) 1998-2006 Sourcefire, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <dnet.h>

#include "snort.h"
#include "decode.h"
#include "inline.h"
#include "rules.h"
#include "stream_api.h"
#include "checksum.h"
#include "bounds.h"
#include "util.h"
#include "mstring.h"
#include "debug.h"
//#include "stream.h"
#define PKT_BUFSIZE 70000

/* Most of the code related to libdnet (resets and icmp unreach) was
+  * taken from sp_respond2.c, actually Jeff Nathan did all of the hard work
+  * We just stole it to create respond2 for dummies via RejectFu*/

/* vars */
ip_t *rawdev;                       /* dnet(3) raw IP handle */
eth_t *ethdev;                      /* dnet(3) ethernet device handle */
rand_t *randh;                      /* dnet(3) rand handle */

static void *tcp_pkt = NULL;            /* TCP packet memory placeholder */
static void *icmp_pkt = NULL;           /* ICMP packet memory placeholder */

static u_int8_t link_offset;            /* offset from L2 to L3 header */
static u_int8_t alignment;              /* force alignment ?? */

static INLINE u_int8_t CalcOriginalTTL(Packet *p);
Packet *tmpP;

#ifdef NFNETLINKQ

/* Oct. 3, 2005 -  Per the GPL (2.0), this code has been modified by NitroSecurity,
and in keeping with the GPL, NitroSecurity releases these changes under version 2
of the GPL. Also, as per version 2 of the GPL, there is no expressed or implied warranty.
If this code decides to have your computer for lunch, it's your problem, not ours.
This code is in working development, and as such is unsuitable for most anything.
NitroSecurity - Dave Remien */

/* Since nfnetlink_queue can't deliver an ipq_packet_msg to us,
just most of the pieces/parts, we'll build an ipq_packet_msg on
the fly from the parts we got. Ugly, as Harald himself says in the libipq emulation.
DAR - 050916

Just to note this - Harald Welte has called for the ip_queue stuff to disappear in
the future - see http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.14
*/


struct my_ipq_packet_msg {
        unsigned long packet_id;        /* ID of queued packet */
        unsigned long mark;             /* Netfilter mark value */
        long timestamp_sec;             /* Packet arrival time (seconds) */
        long timestamp_usec;            /* Packet arrvial time (+useconds) */
        unsigned int hook;              /* Netfilter hook we rode in on */
        char indev_name[IFNAMSIZ];      /* Name of incoming interface */
        char outdev_name[IFNAMSIZ];     /* Name of outgoing interface */
        unsigned short hw_protocol;     /* Hardware protocol (network order) */
        unsigned short hw_type;         /* Hardware type */
        unsigned char hw_addrlen;       /* Hardware address length */
        unsigned char hw_addr[8];       /* Hardware address */
        size_t data_len;                /* Length of packet data */
        unsigned char payload[PKT_BUFSIZE];    /* Optional packet data */
}  ipq_pkt;
static unsigned int glid = 0;
char ifnames[32][IF_NAMESIZE];
int nl_fd, rv;
struct nfq_handle *nfqh;
struct nfq_q_handle *qhndl;
struct nfnl_handle *nh;

#endif /* NFNETLINKQ */

#ifndef IPFW
/* used by log unified - it only uses it for the hardware address */
ipq_packet_msg_t *g_m = NULL;
#endif

/* predeclarations */
#ifndef IPFW
void HandlePacket(ipq_packet_msg_t *);
void TranslateToPcap(ipq_packet_msg_t *, struct pcap_pkthdr *);
#else
void HandlePacket();
void TranslateToPcap(struct pcap_pkthdr *phdr, ssize_t len);
#endif /* IPFW */
void ResetIV(void);


/**
 *  InlineMode - determine if we are in inline mode
 *  
 *  @returns 1 if we are in inline mode, 0 otherwise
 */
int InlineMode()
{
	if (pv.inline_flag)
		return 1;

	return 0;
}

int InlineModeSetPrivsAllowed()
{
    if (pv.inline_flag)
        return 0;

    return 1;
}

#ifndef IPFW
/* bypassed by NFQ */
void TranslateToPcap(ipq_packet_msg_t *m, struct pcap_pkthdr *phdr)
{
    static struct timeval t;
    if (!m->timestamp_sec) 
    {
        memset (&t, 0, sizeof(struct timeval));
        gettimeofday(&t, NULL);
        phdr->ts.tv_sec = t.tv_sec;
        phdr->ts.tv_usec = t.tv_usec;
    }
    else 
    {
        phdr->ts.tv_sec = m->timestamp_sec;
        phdr->ts.tv_usec = m->timestamp_usec;
    }
    phdr->caplen = m->data_len;
    phdr->len = m->data_len;
}
#else /* IPFW */
void TranslateToPcap(struct pcap_pkthdr *phdr, ssize_t len)
{
    static struct timeval t;
    memset (&t, 0, sizeof(struct timeval));
    gettimeofday(&t, NULL);
    phdr->ts.tv_sec = t.tv_sec;
    phdr->ts.tv_usec = t.tv_usec;
    phdr->caplen = len;
    phdr->len = len;

}
#endif /* IPFW */

static INLINE u_int8_t CalcOriginalTTL(Packet *p)
{        
    switch (tmpP->iph->ip_ttl / 64)
    {
        case 3:              
            return 255;
        case 2:
            return 192;
        case 1:
            return 128;
        default:
            return 64;
    }
}

void RejectFuRestart()
{

    /* device and raw IP handles */                 
    if (rawdev != NULL)
        rawdev = ip_close(rawdev);
    if (ethdev != NULL)
        ethdev = eth_close(ethdev);

    /* free packet memory */

    if (tcp_pkt != NULL)
    {
        tcp_pkt -= alignment;      
        free(tcp_pkt);
        tcp_pkt = NULL;
    }
    if (icmp_pkt != NULL)
    {
        icmp_pkt -= alignment;
        free(icmp_pkt);
        icmp_pkt = NULL;
    }

    /* Close random handle */
    if (randh != NULL)
        randh = rand_close(randh);

    return;
}

void ResetIV()
{
    iv.drop = 0;
    iv.rejectsrc = 0;
    iv.rejectdst = 0;
    iv.reinject = 0;
    iv.replace = 0;
}


/*
 *    Function: void InitInlinePostConfig
 *
 *    Purpose: perform initialization tasks that depend on the configfile
 *
 *    Args: none
 *    
 *    Returns: nothing void function
 */
void InitInlinePostConfig(void)
{

    printf("InitInline stage 2: InitInlinePostConfig starting...\n");

    /* Let's initialize dnet set the size of the tcp/icmp packets and
     * allocate memory for the data.
     */  
#ifndef IPFW
    if(pv.layer2_resets)
    {
        link_offset = ETH_HDR_LEN;
        alignment = 2;
        if ((randh = rand_open()) == NULL)
        {
            printf("could no open random handle\n");
        }

    }
    else
    {
#ifdef DEBUG_GIDS
        printf("opening raw socket in IP-mode\n");
#endif
        link_offset = 0;
        alignment = 0;
        
        if ((rawdev = ip_open()) == NULL)
        {
           printf("InitInline: Unable to open raw socket for dnet.\n");
        }
 
    }
#else /* IPFW */
        link_offset = 0;
        alignment = 0;

        if ((rawdev = ip_open()) == NULL)
        {
           printf("InitInline: Unable to open raw socket for dnet.\n");
        }

#endif /* IPFW */
    tcp_pkt = SnortAlloc(alignment + link_offset + IP_HDR_LEN + TCP_HDR_LEN);
    tcp_pkt += alignment;
    icmp_pkt = SnortAlloc(alignment + link_offset + IP_HDR_LEN + ICMP_LEN_MIN + 68);
    icmp_pkt += alignment;
}

#ifdef NFNETLINKQ
/*
 * This "cb" routine is a callback function, which is called from the netlink_queue
 * code to get the various parts of the packet from the skbuff needed in user space.
 * It's based on code found in utils/nfqnl_test.c, from the libnetfilter_queue tar ball.
 * I liked the name xyzzy, from Adventure, just to see if any oldtimers recognized it,
 * but it probably should be "callback" or "cb".
 */ 
  
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{  
   int iret;
   u_int32_t ifi;
   char *junkdata = NULL;
   struct timeval ts;
   struct pcap_pkthdr PHdr;
   static ipq_packet_msg_t *m = &ipq_pkt;
   struct nfqnl_msg_packet_hdr *ph = NULL;
   struct nfqnl_msg_packet_hw *hw = NULL;
   
   /* call this here in case we are ever going to
    * be called more than once per read from the kernel.
    */
   ResetIV();

   PHdr.caplen = PHdr.len = nfq_get_payload(nfa, &junkdata);
   memcpy(ipq_pkt.payload, junkdata, PHdr.len);
      
   ph = nfq_get_msg_packet_hdr(nfa);
   glid = ntohl(ph->packet_id);
   // no one needs this in Snort, afaics -- VJ
   //ipq_pkt.packet_id = glid;
   //ipq_pkt.hw_protocol = ntohs(ph->hw_protocol);
   //ipq_pkt.hook = ph->hook;
   //ipq_pkt.mark = nfq_get_nfmark(nfa);
   
   /* TODO: we only use this for rejects, so we might move
    * this to the reject code */
   ifi = nfq_get_indev(nfa);
   strlcpy(ipq_pkt.indev_name, ifnames[ifi], sizeof(ipq_pkt.indev_name));
   ifi = nfq_get_outdev(nfa);
   strlcpy(ipq_pkt.outdev_name, ifnames[ifi], sizeof(ipq_pkt.outdev_name));

   hw = nfq_get_packet_hw(nfa);
   if (hw) {
       ipq_pkt.hw_addrlen = ntohs(hw->hw_addrlen);
       memcpy(ipq_pkt.hw_addr, hw->hw_addr,  ipq_pkt.hw_addrlen);
   }

   iret = nfq_get_timestamp(nfa, &ts);
   if (!iret) {
       PHdr.ts.tv_sec = (long)(ts.tv_sec);
       PHdr.ts.tv_usec = (long)(ts.tv_usec);
   } else {
       memset (&ts, 0, sizeof(struct timeval));
       gettimeofday(&ts, NULL);
       PHdr.ts.tv_sec = ts.tv_sec;
       PHdr.ts.tv_usec = ts.tv_usec;
   }

   //DebugMessage(DEBUG_STREAM, "callback packet size len %u caplen %u\n", PHdr.len, PHdr.caplen);

   /* we don't call TranslatetoPcap packet */
   ProcessPacket(NULL, &PHdr, (u_char *)m->payload, NULL);
   HandlePacket(m);

   return(0);
}
#endif /* NFNETLINKQ */

/* InitInline is called before the Snort_inline configuration file is read. */
int InitInline()
{
#ifndef IPFW
    int status;
#endif

    printf("Initializing Inline mode \n");

#ifndef IPFW
#ifdef NFNETLINKQ
   /* Get interface names as strings; only the numbers are in the skbuff */

     struct if_nameindex *if_nameindex(void);
     struct if_nameindex *blah;
     int i,j;

     for (j = 0; j < 32; j++)
        for(i = 0; i < IF_NAMESIZE; i++)ifnames[j][i] = 0;

     blah = if_nameindex();
     for(i = 0; i < 32; i++){

        if(blah[i].if_index == 0)break;
        strlcpy(ifnames[blah[i].if_index], blah[i].if_name, IF_NAMESIZE);

     }
     if_freenameindex(blah);
#else

    ipqh = ipq_create_handle(0, PF_INET);
    if (!ipqh)
    {
        ipq_perror("InlineInit: ");
        ipq_destroy_handle(ipqh);
        exit(1);
    }
 
    status = ipq_set_mode(ipqh, IPQ_COPY_PACKET, PKT_BUFSIZE);
    if (status < 0)
    {
        ipq_perror("InitInline: ");
        ipq_destroy_handle(ipqh);
        exit(1);
    }

/*
 * netlink_queue initialization moved into beginning of NfnetlinkQLoop() - DAR
 */

#endif /* NFNETLINKQ */
#endif /* IPFW */

    ResetIV();

    /* Just in case someone wants to write to a pcap file
     * using DLT_RAW because iptables does not give us datalink layer.
     */
    pd = pcap_open_dead(DLT_RAW, SNAPLEN);

    return 0;
}

#ifndef IPFW
#ifndef NFNETLINKQ
void IpqLoop()
{
    int status = 0;
    struct pcap_pkthdr PHdr;
    unsigned char buf[PKT_BUFSIZE];
    static ipq_packet_msg_t *m;

#ifdef DEBUG_GIDS
    printf("Reading Packets from ipq handle \n");
#endif


    while(1)
    {
        ResetIV();
        status = ipq_read(ipqh, buf, PKT_BUFSIZE, 1000000);
        if (status < 0)
        {
            ipq_perror("IpqLoop: ");
        }
        /* man ipq_read tells us that when a timeout is specified
         * ipq_read will return 0 when it is interupted. */
        else if(status == 0)
        {
            /* Do the signal check. If we don't do this we will
             * evaluate the signal only when we receive an actual
             * packet. We don't want to depend on this. */
            sig_check();
        }
        else
        {
            switch(ipq_message_type(buf))
            {
                case NLMSG_ERROR:
                    fprintf(stderr, "Received error message %d\n", 
                            ipq_get_msgerr(buf));
                    break;

                case IPQM_PACKET: 
                    m = ipq_get_packet(buf);
                    g_m = m;
#ifdef DEBUG_INLINE
                    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", m->hw_addr[0], m->hw_addr[1],
                           m->hw_addr[2], m->hw_addr[3], m->hw_addr[4], m->hw_addr[5]);
#endif              

                    TranslateToPcap(m, &PHdr);
                    PcapProcessPacket(NULL, &PHdr, (u_char *)m->payload);
                    HandlePacket(m);
                    break;
            } /* switch */
        } /* if - else */
    } /* while() */
}
#endif /* NFNETLINKQ */
#endif /* IPFW */


#ifndef IPFW
#ifdef NFNETLINKQ
void NfnetlinkQLoop()
{
    struct timeval tv;
    int rcvstatus = 0;
    char buf[PKT_BUFSIZE] = "";

#ifdef DEBUG_GIDS
    printf("Reading Packets from nfq handle \n");
#endif

    /* log unified needs this */
    g_m = &ipq_pkt;
    memset(&ipq_pkt, 0, sizeof(ipq_pkt));

    /* The following sequence was "borrowed" from Harald Welte's 
     * utils/nfqnl_test.c, same as the callback routine - 
     * which is setup in the nfq_create_queue() call below.
     */

    nfqh = nfq_open();
    if (!nfqh) {
        printf("[%d] error during nfq_open()\n",getpid());
        exit(1);
    }

    if (nfq_unbind_pf(nfqh, AF_INET) < 0) {
        printf("[%d] error during nfq_unbind_pf()\n",getpid());
        exit(1);
    }

    if (nfq_bind_pf(nfqh, AF_INET) < 0) {
        printf("[%d] error during nfq_bind_pf()\n",getpid());
        exit(1);
    }

    qhndl = nfq_create_queue(nfqh, nfqueue_num, &cb, NULL);
    if (!qhndl) {
        printf("[%d] error during nfq_create_queue() (queue %d busy ?)\n",
            getpid(),nfqueue_num);
        exit(1);
    }

    if (nfq_set_mode(qhndl, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("[%d] can't set packet_copy mode\n",getpid());
        exit(1);
    }

#ifdef HAVE_NFQ_MAXLEN
    if (pv.queue_maxlen > 0) {
        /* non-fatal if it fails */
        if (nfq_set_queue_maxlen(qhndl, pv.queue_maxlen) < 0) {
            printf("[%d] Warning: can't set queue maxlen: your kernel probably "
                 "doesn't support setting the queue length\n", getpid());
        }
    }
#endif

    nh = nfq_nfnlh(nfqh);
    nl_fd = nfnl_fd(nh);

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if ( setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) ) == -1) {
        printf("[%d] can't set socket timeout: %s\n",getpid(), strerror(errno));
        exit(1);
    }

    /* The following loop basically gets executed forever, or until
     * snort blows or gets signalled to exit. As with libipq, 
     * netlink_queue requires that every single packet asked for
     * from the queue be acknowledged. A future enhancement
     * might be to ask for multiple packets at once, then
     * either ack them individually as processed (to reduce latency),
     * or possibly all-at-once, in the hope of reducing the user-space
     * to kernel overhead time and increasing throughput. The underlying
     * nfnetlink code can already deal with multiple packets, so this
     * might not be too painful to do. Another simplification might be to
     * build the packet as a pcap packet directly, avoiding the ipq
     * emulation; and subsequent "TranslateToPcap(). So far, though,
     * profiling seems to indicate that the things snort is doing with the 
     * packet take the vast majority of CPU cycles. 
     */

    while(1)
    {
	/* zero the the buffer, just to be on the safe side.
         * Pretty sure this isn't needed. */
        //memset(buf, 0, sizeof(buf));
        rcvstatus = recv(nl_fd, buf, PKT_BUFSIZE, 0);
        //printf("recvd %i bytes glid = %u\n", rcvstatus, glid);
        if (rcvstatus < 0)
        {
            /* if the errno is EINTR or EWOULDBLOCK check if we
             * received a signal */
            if (errno == EINTR || errno == EWOULDBLOCK) {
                //printf("waiting for packets...\n");
                sig_check();
            } else {
                printf("[%d] packet recv contents failure: %s\n",getpid(), strerror(errno));
            }
        }
	else
        {
            /* handle_packet calls the callback function */
            nfq_handle_packet(nfqh, buf, rcvstatus);
        }

    } /* while() */
}
#endif /* NFNETLINKQ */
#endif /* IPFW */


#ifdef IPFW
/* Loop reading packets from IPFW
   - borrowed mostly from the TCP-MSSD daemon in FreeBSD ports tree
    Questions, comments send to:  nick@rogness.net
*/
void IpfwLoop()
{
    char pkt[IP_MAXPACKET];
    struct pcap_pkthdr PHdr;
    ssize_t pktlen; 
    struct sockaddr_in sin;
    socklen_t sinlen;
    int rtsock;
    int ifindex;
    fd_set fdset;
    ifindex = 0;
    rtsock = -1;

#ifdef DEBUG_GIDS
    printf("Reading Packets from ipfw divert socket \n");
#endif

    /* Build divert socket */
    if ((divert_socket = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) 
    {
        perror("IpfwLoop: can't create divert socket");
        exit(-1);
    }

    /* Fill in necessary fields */
    bzero(&sin, sizeof(sin));
    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(pv.divert_port);

    /* Bind that biatch */
    if (bind(divert_socket, (struct sockaddr *)&sin, sizeof(sin)) == -1) 
    {
        perror("IpfwLoop: can't bind divert socket");
        exit(-1);
    }

    /* Lets process the packet */
    while (1) 
    {
        ResetIV();
        FD_ZERO(&fdset);
        FD_SET(divert_socket, &fdset);
        if (rtsock != -1)
        {
            FD_SET(rtsock, &fdset);
        }

        if (select(32, &fdset, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)NULL) == -1)
        {
            printf("select failed");
            continue;
        }

        if (FD_ISSET(divert_socket, &fdset)) 
        {
            sinlen = sizeof(sin);

            if ((pktlen = recvfrom(divert_socket, pkt, sizeof(pkt), 0,(struct sockaddr *)&sin, &sinlen)) == -1)
            {
                if (errno != EINTR)
                {
                     printf("IpfwLoop: read from divert socket failed");
                     continue;
                }
            }

            TranslateToPcap(&PHdr,pktlen);
            PcapProcessPacket(NULL, &PHdr, pkt);
            HandlePacket();

	    /* If we don't drop and don't reject, reinject it back into ipfw,
  	     * otherwise, we just drop it
	    */
            if (! iv.drop && ! iv.rejectsrc)
            {
		if (iv.reinject) 
		{
		    if (pv.ipfw_reinject_rule)
		    {
			if (pv.ipfw_reinject_rule < sin.sin_port)
			{
                     	    printf("IpfwLoop: reinjection loop: start=%d,end=%d\n",sin.sin_port,pv.ipfw_reinject_rule);
                            continue;
			}
		    
			sin.sin_port=pv.ipfw_reinject_rule;
		    }
		}

                if (sendto(divert_socket, pkt, pktlen, 0,(struct sockaddr *)&sin, sinlen) == -1)
                {
                    printf("IpfwLoop: write to divert socket failed");
                }
            }
         } /* end if */

    } /* end while */
}
#endif

/*
 *    Function: static void RejectFu(ipq_packet_msg_t *m)
 *
 *    Purpose: send a reject packet (tcp-reset or icmp-unreachable)
 *
 *    Args: the ipq_packet_msg_t m for determining the output interface
 *          and the source mac for our packet.
 *
 *    Returns: nothing void function
 *
 *    TODO: make it also work on *BSD.
 */
#ifndef IPFW
static void
RejectFu(ipq_packet_msg_t *m, int mode)
#else 
static void
RejectFu(int mode)
#endif
{
    int proto = 0;
    int noreverse = 0;
    IPHdr *iph;
#ifndef IPFW
    int i = 0;
    char **macbytes;
    int num_macbytes;
    EtherHdr *eh;
    char *device; /*int name for eth_open*/
    eth_addr_t srclinkaddr; /*used to get mac address for layer2*/
    u_char enet_src[6]; /* mac addr for creating the ethernet packet. */

#endif /* IPFW */

    if(tmpP->iph == NULL)
      return;

    proto = tmpP->iph->ip_proto;


    if(mode == 1)
    {
      noreverse = 1;
    }

#ifndef IPFW
    //if((Stream4InlineMode()) && (opdsize))
    //{
    //    tmpP->dsize = opdsize;
    //} 
    if(link_offset) 
    {
        /* we can't get the proper dst mac address for a non reversed reset */
        if(noreverse)
        {
            printf("layer2 resets don't work for non reversed packets\n");
            return;
        }

        /* read int name from iptables, indev and outdev are the same in bridge mode */
        if(m->indev_name[0] != '\0') 
           device = m->indev_name;
        else
           device = m->outdev_name;

        if ((ethdev = eth_open(device)) != NULL) 
        {
          if (eth_get(ethdev, &srclinkaddr)< 0)
          {
#ifdef DEBUG_GIDS
            printf("failed to get macaddy\n");
#endif
          }
          else
          {
#ifdef DEBUG_GIDS
            printf("mac addy of src int is %s\n",eth_ntoa(&srclinkaddr));
#endif
          }
        }

        /* copy the mac out of the snort.conf
         * but only if the mac wasn't supplied in the configfile */
         if(pv.enet_src[0] == 0 && pv.enet_src[1] == 0 && pv.enet_src[2] == 0 && pv.enet_src[3] == 0 && pv.enet_src[4] == 0 && pv.enet_src[5] == 0)
         {
             /* mac is blank or user set 00:00:00:00:00, let's set it */
             macbytes = mSplit(eth_ntoa(&srclinkaddr), ":", 6, &num_macbytes, '\\');

             if (num_macbytes < 6)
             {
#ifdef DEBUG_GIDS
                 printf("That is one crazy mac addy");
#endif
             }
             else
             {
                 for (i = 0; i < 6; i++)
                 enet_src[i] = (u_int8_t) strtoul(macbytes[i], NULL, 16);
             }
             mSplitFree(&macbytes, num_macbytes);
         }
         else
         {
               for(i = 0; i < 6; i++)
                 enet_src[i] = pv.enet_src[i];
         }

    }
#endif /* IPFW */
    switch(proto)
    {
        case IPPROTO_TCP:
            if (!tmpP->frag_flag)
            {
                TCPHdr *tcp;
                size_t sz = IP_HDR_LEN + TCP_HDR_LEN;
                ssize_t n;
                u_int32_t i, ack, seq;
                u_int16_t window, dsize;
                iph = (IPHdr *)(tcp_pkt + link_offset);
                tcp = (TCPHdr *)(tcp_pkt + IP_HDR_LEN + link_offset);
#ifndef IPFW               
                if(link_offset)
                {
                   eh = (EtherHdr *)tcp_pkt;
                   eh->ether_type = htons(ETH_TYPE_IP);
                   memcpy(eh->ether_src, enet_src, 6);
                   memcpy(eh->ether_dst, m->hw_addr, 6);
                }
#endif
                SET_IP_VER(iph, 4);
                SET_IP_HLEN(iph, (IP_HDR_LEN >> 2));  
                iph->ip_proto = IPPROTO_TCP;     

                /* points to the start of the TCP header */
                tcp = (TCPHdr *)(tcp_pkt + IP_HDR_LEN + link_offset);
                tcp->th_flags = TH_RST|TH_ACK;
                SET_TCP_OFFSET(tcp, (TCP_HDR_LEN >> 2));

                /* save p->dsize */
                dsize = tmpP->dsize;
                if(noreverse)
                {
                   /* Keep the source and destination IP addr for attack-response rules */
                   iph->ip_src.s_addr = tmpP->iph->ip_src.s_addr;
                   iph->ip_dst.s_addr = tmpP->iph->ip_dst.s_addr;

                   if(tmpP->tcph == NULL)return;
                   tcp->th_sport = tmpP->tcph->th_sport;
                   tcp->th_dport = tmpP->tcph->th_dport;
                   seq = ntohl(tmpP->tcph->th_seq);
                   ack = ntohl(tmpP->tcph->th_ack);
                   iph->ip_ttl = CalcOriginalTTL(tmpP);
                   tcp->th_win = tmpP->tcph->th_win;

                   /* save the window size for all calculations */
                   window = ntohs(tcp->th_win);
                }

                else 
                {
                   /* Reverse the source and destination IP addr for attack-response rules */
                   iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
                   iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;

                   if(tmpP->tcph == NULL)return;
                   tcp->th_sport = tmpP->tcph->th_dport;
                   tcp->th_dport = tmpP->tcph->th_sport;
                   seq = ntohl(tmpP->tcph->th_ack);
                   ack = ntohl(tmpP->tcph->th_seq) + tmpP->dsize;
                   iph->ip_ttl = CalcOriginalTTL(tmpP);
                   tcp->th_win = tmpP->tcph->th_win;

                   /* save the window size for all calculations */
                   window = ntohs(tcp->th_win);
                }

                /* Master Jeff say's calculating sequence number variations is important */
                for (i = 0; i < 4; i++)
                {
                    if (link_offset)
                    {
                        iph->ip_id = rand_uint16(randh);
                    }
                    switch (i)
                    {
                        case 0:
                        break;
                      case 1:
                        seq += dsize;
                        break;
                      case 2:
                        seq += (dsize << 1);
                        ack += (dsize << 1);
                        break;
                      case 3:
                        seq += (dsize << 1);
                        ack += (dsize << 1);
                        break;
                      case 4:
                        seq += (dsize << 2);
                        ack += (dsize << 2);
                        break;
                      default:
                        seq += (window >> 1);
                        ack += (window >> 1);
                      break;
                   }

#ifndef IPFW
                   tcp->th_seq = htonl(seq);
                   tcp->th_ack = htonl(ack);

#else
                   /* fix resets on FreeBSD */
                   tcp->th_ack = htonl(ack + 1);
#endif /* IPFW */

                   iph->ip_len = htons(sz);
                   ip_checksum(tcp_pkt + link_offset, sz);

                   /* sending the reset */
                   if (link_offset)
                      n = eth_send(ethdev, tcp_pkt, sz + link_offset);
                   else
                      n = ip_send(rawdev, tcp_pkt, sz);

                   if (n < sz)
                       printf("failed to send reset\n");
                 }
            } /* end if !tmpP->frag_flag */
            break;

        case IPPROTO_UDP:
            if (!tmpP->frag_flag)
            {
               ICMPHdr *icmph;
               u_int16_t payload_len;
               size_t sz;
               ssize_t n;

               /* only send ICMP port unreachable responses for TCP and UDP */
               if (tmpP->iph->ip_proto == IPPROTO_ICMP && tmpP->icmph->code == ICMP_UNREACH_PORT)
               {
#ifdef DEBUG_GIDS
                  printf("ignoring icmp_port set on ICMP packet.\n");
#endif
                  return;
               }

               iph = (IPHdr *)(icmp_pkt + link_offset);
               icmph = (ICMPHdr *)(icmp_pkt + IP_HDR_LEN + link_offset);

               /* points to the start of the IP header */
               iph = (IPHdr *)(icmp_pkt + link_offset);
               SET_IP_VER(iph, 4);
               SET_IP_HLEN(iph, (IP_HDR_LEN >> 2));
               iph->ip_proto = IPPROTO_ICMP;

               /* points to the start of the TCP header */
               icmph = (ICMPHdr *)(icmp_pkt + IP_HDR_LEN + link_offset);
               icmph->type = ICMP_UNREACH;

               if(noreverse)
               {
                  iph->ip_src.s_addr = tmpP->iph->ip_src.s_addr;
                  iph->ip_dst.s_addr = tmpP->iph->ip_dst.s_addr;
               }
               else
               {
                  iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
                  iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;
               }

               iph->ip_ttl = CalcOriginalTTL(tmpP);

               icmph->code = ICMP_UNREACH_PORT;
#ifndef IPFW
               if(link_offset)
               {
                  /* setup the Ethernet header */
                  eh = (EtherHdr *)icmp_pkt;
                  eh->ether_type = htons(ETH_TYPE_IP);
                  if(noreverse)
                  {
                     memcpy(eh->ether_src, m->hw_addr, 6);
                     memcpy(eh->ether_dst, enet_src, 6);
                  }
                  else
                  {
                     memcpy(eh->ether_src, enet_src, 6);
                     memcpy(eh->ether_dst, m->hw_addr, 6);
                  }
                  iph->ip_id = rand_uint16(randh);
               }
#endif
               if ((payload_len = ntohs(tmpP->iph->ip_len) - (IP_HLEN(tmpP->iph) << 2)) > 8)
                    payload_len = 8;

               memcpy((char *)icmph + ICMP_LEN_MIN, tmpP->iph, (IP_HLEN(tmpP->iph) << 2)
                     + payload_len);
               sz = IP_HDR_LEN + ICMP_LEN_MIN + (IP_HLEN(tmpP->iph) << 2) + payload_len;

               iph->ip_len = htons(sz);
               ip_checksum(icmp_pkt + link_offset, sz);
               sz += link_offset;

               if (link_offset)
                  n = eth_send(ethdev, icmp_pkt, sz);
               else
                  n = ip_send(rawdev, icmp_pkt, sz);

               if (n < sz)
                  printf("failed to send icmp reset");
            }
            break;
    } /* end switch(proto) */
    if(link_offset)
    {
        eth_close(ethdev);
    }
}


#ifndef IPFW
void HandlePacket(ipq_packet_msg_t *m)
#else
void HandlePacket()
#endif
{
#ifndef IPFW
    int status;
#endif
    if (iv.drop == 1)
    {
#ifndef IPFW
#ifdef NFNETLINKQ
        status = nfq_set_verdict(qhndl, glid, NF_DROP, 0, NULL);
        if (status < 0)
        {
            fprintf(stderr,"NF_DROP: ");
        }
#else
        status = ipq_set_verdict(ipqh, m->packet_id, NF_DROP, 0, NULL);
        if (status < 0)
        {
            ipq_perror("NF_DROP: ");
        }
#endif /* NFNETLINKQ */
#endif /* IPFW */
        if (iv.rejectsrc == 1)
        {
#ifndef IPFW
            RejectFu(m,0);
#else
            RejectFu(0);
#endif /* IPFW */
        }
        if (iv.rejectdst)
        {
#ifndef IPFW
            RejectFu(m,1);
#else
            RejectFu(1);
#endif /* IPFW */
        }
    }
#ifndef IPFW
    else if (iv.replace == 0)
    {
#ifdef NFNETLINKQ
        status = nfq_set_verdict(qhndl, glid, NF_ACCEPT, 0, NULL);
        if (status < 0)
        {
            fprintf(stderr, "NF_ACCEPT: ");
        }
#else
        status = ipq_set_verdict(ipqh, m->packet_id, NF_ACCEPT, 0, NULL);
        if (status < 0)
        {
            ipq_perror("NF_ACCEPT: ");
        }
#endif /* NFNETLINKQ */
    }
    else /* implied replace */
    {
#ifdef NFNETLINKQ
        status = nfq_set_verdict(qhndl, glid, NF_ACCEPT, m->data_len, m->payload);
        if (status < 0)
        {
            fprintf(stderr,"NF_ACCEPT: ");
        }
#else
        status = ipq_set_verdict(ipqh, m->packet_id, NF_ACCEPT, 
                 m->data_len, m->payload);
        if (status < 0)
        {
            ipq_perror("NF_ACCEPT: ");
        }
#endif /* NFNETLINKQ */
    }

#endif
}


int InlineWasPacketDropped()
{
    if (iv.drop)
        return 1;

    return 0;
}

int InlineDrop(Packet *p)
{
    //printf("InlineDrop(): dropping\n");
    iv.drop = 1;
    p->packet_flags |= PKT_INLINE_DROP;

    if (p->ssnptr && stream_api)
    {
        stream_api->drop_packet(p);

        if (!(p->packet_flags & PKT_STATELESS))
            stream_api->drop_traffic(p->ssnptr, SSN_DIR_BOTH);
    }
    return 0;
}

/* drop a packet without ever dropping the
 * tcp session as well. This makes sense for
 * packets that are dropped because they are
 * out of order. Those aren't bad, and we will
 * probably accept later retransmissions */
int InlineDropPacketOnly(Packet *p) {
    iv.drop = 1;
    p->packet_flags |= PKT_INLINE_DROP;
    return 0;
}

int InlineReject(Packet *p)
{
    //printf("InlineReject(): rejecting\n");
    iv.rejectsrc = 1;
    iv.drop = 1;
    tmpP = p;
    return 0;
}

int InlineRejectBoth(Packet *p)
{
    iv.rejectsrc = 1;
    iv.rejectdst = 1;
    iv.drop = 1;
    tmpP = p;
    return 0;
}

int InlineRejectSrc(Packet *p)
{
    iv.rejectsrc = 1;
    iv.drop = 1;
    tmpP = p;
    return 0;
}

int InlineRejectDst(Packet *p)
{
    iv.rejectdst = 1;
    iv.drop = 1;
    tmpP = p;
    return 0;
}

#ifdef IPFW
int InlineReinject(Packet *p)
{
    iv.rejectsrc = 0;
    iv.rejectdst = 0;
    iv.drop = 0;
    iv.reinject = 1;
    tmpP = p;
    return 0;
}
#endif /* IPFW */

int InlineAccept()
{
    iv.drop = 0;
    return 0;
}

int InlineReplace()
{
    iv.replace = 1;
    return 0;
}

#else /* GIDS */

#include "snort.h"
#include "stream_api.h"

extern int g_drop_pkt;
extern PV  pv;

/*
**  Let's define these for non-inline use.
*/
int InlineMode()
{
	if (pv.inline_flag)
		return 1;

	return 0;
}

int InlineModeSetPrivsAllowed()
{
    return 1;
}

int InlineWasPacketDropped()
{
    if (g_drop_pkt)
        return 1;

    return 0;
}

int InlineDrop(Packet *p)
{
    g_drop_pkt = 1;

    p->packet_flags |= PKT_INLINE_DROP;

    if (p->ssnptr && stream_api)
    {
        stream_api->drop_packet(p);

        if (!(p->packet_flags & PKT_STATELESS))
            stream_api->drop_traffic(p->ssnptr, SSN_DIR_BOTH);
    }
    return 0;
}

int InlineDropPacketOnly(Packet *p)
{
    g_drop_pkt = 1;
    p->packet_flags |= PKT_INLINE_DROP;
    return 0;
}

#endif /* GIDS */

