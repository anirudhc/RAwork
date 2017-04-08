#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/udp.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;         //struct holding set of hook function options


//function to be called by hook
static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

    struct sk_buff *sock_buff;
    sock_buff = skb;
    unsigned char *port = "\xcf\x08";
    
    struct iphdr* iph = ip_hdr(skb);
    unsigned long start;
    unsigned cycles_low, cycles_high;
    struct udphdr *udp_header;


    if(iph->protocol == 17)
    {        


        udp_header = (struct udphdr *)(sock_buff->data + (iph->ihl *4));
        if((udp_header->dest) == *(unsigned short*)port){
        printk("recieved a packet: source:%d :: dest:%d\n", ntohs(udp_header->source) ,ntohs(udp_header->dest));
        /*
        const int size = 20*1024*1024; // Allocate 20M. Set much larger then L2
        char *c = (char *)vmalloc(size);
        int i;
        for (i = 0; i < size; i++)            
            c[i]=0;
        vfree(c);
         */      
         asm volatile ("WBINVD\n\t");



            asm volatile(
	    "CPUID\n\t"
            "RDTSC\n\t"
            "mov %%edx, %0\n\t"            
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax","%rbx","%rcx", "%rdx");            
            asm volatile(
	    "CPUID\n\t"
            "RDTSC\n\t"
            "mov %%edx, %0\n\t"            
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax","%rbx","%rcx", "%rdx");            
            asm volatile(
	    "CPUID\n\t"
            "RDTSC\n\t"
            "mov %%edx, %0\n\t"            
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax","%rbx","%rcx", "%rdx");            


            asm volatile(
	    "CPUID\n\t"
            "RDTSC\n\t"
            "mov %%edx, %0\n\t"            
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax","%rbx","%rcx", "%rdx");            
            start = ( ((uint64_t)cycles_high << 32) | cycles_low );
            
            printk(KERN_INFO "entry_point: %lu\n", start);

            
        }
    }
  return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = 0;                            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook

  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);                     //cleanup . unregister hook
}


