#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/udp.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;         //struct holding set of hook function options
unsigned char *port = "\xcf\x08";
struct sk_buff *sock_buff;
struct udphdr *udp_header;

//function to be called by hook
static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

  sock_buff = skb;
  struct iphdr* iph = ip_hdr(skb);
  unsigned long end;
  unsigned cycles_low, cycles_high;
  if (iph->protocol == 17)
  {
    udp_header = (struct udphdr *)(sock_buff->data + (iph->ihl * 4));
    printk("Sending a packet: %d ::: Source port: %d\n", ntohs(udp_header->source) ,ntohs(udp_header->dest));
    if ((udp_header->dest) == *(unsigned short*)port) {
      asm volatile (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
      end = ( ((uint64_t)cycles_high << 32) | cycles_low );

      printk(KERN_INFO "end_point: %llu\n", end);

    }
  }
  return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = NF_INET_POST_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_LAST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook

  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);                     //cleanup . unregister hook
}
