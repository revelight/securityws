


// 							NET FILTER
// ===================================================================

#include "net_netfilter_handler.h"


// NetFilter Hook-Ops
//	(consider: using array and netfilter's plural function versions: nf_(un)register_hooks)
static struct nf_hook_ops nfhops_pre;		// pre routing
static struct nf_hook_ops nfhops_local_out;	// created locally


// 						hook functions
// ===================================================================
// hook function - FIREWALL DECIDE
unsigned int nf_hook_func_fw_decider(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{

	//if (in == NULL || out == NULL) printk("NET DEVICE NULL DETECTED!");
	//printk(KERN_INFO "in name %s\n",in->name);
	//printk(KERN_INFO "out name %s\n",out->name);

	return fw_trafficman_decidePacket(hooknum, skb, in, out, okfn);
}
// ===================================================================



// 						create / destroy
// ===================================================================

// setup and register hook_ops to netfilter hooks
int nf_init_hooks(void){

	// .. nfhops_pre
	nfhops_pre.hook = nf_hook_func_fw_decider;
	nfhops_pre.pf = PF_INET; // ipv4 Family
	nfhops_pre.hooknum = NF_INET_PRE_ROUTING; // net_filter hook point
	nfhops_pre.priority = NF_IP_PRI_FIRST; // this hook-func's priority in hook point
	if (nf_register_hook(&nfhops_pre)!=0) {return RETVAL_ERR;} // register the hook with NF


	// .. nfhops_local_out
	nfhops_local_out.hook = nf_hook_func_fw_decider;
	nfhops_local_out.pf = PF_INET;
	nfhops_local_out.hooknum = NF_INET_LOCAL_OUT;
	nfhops_local_out.priority = NF_IP_PRI_FIRST;
	if (nf_register_hook(&nfhops_local_out)!=0) {return RETVAL_ERR;}


	return RETVAL_OK;
}

void nf_destroy_hooks(void){
	// Unregister hook_ops from netfilter hooks
	//  * [unreg func is void return]
	nf_unregister_hook(&nfhops_pre);
	nf_unregister_hook(&nfhops_local_out);
}

// ===================================================================




unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	VPRINT1(KERN_INFO "TEST - hook_func");

	if (!skb) return NF_ACCEPT;

	struct iphdr *hdr_ip;
	struct tcphdr *hdr_tcp;
	int tcplen;
	hdr_ip = (struct iphdr *)skb_network_header(skb);


	if (!hdr_ip) return NF_ACCEPT;
	if (hdr_ip->protocol != 6) return NF_ACCEPT;

	hdr_tcp = (struct tcphdr *)(skb_transport_header(skb)+20); //for incoming packets use +20
	if (!hdr_tcp) return NF_ACCEPT;


	if (hdr_tcp->dest == htons(80)) {
		VPRINT1(KERN_INFO "faking packet");

		skb_linearize(skb);

		//changing of routing
		hdr_ip->daddr = htonl(167837955); //change to yours IP
		hdr_tcp->dest = htons(8001); //change to yours listening port

		//here start the fix of checksum for both IP and TCP
		tcplen = (skb->len - ((hdr_ip->ihl )<< 2));
        hdr_tcp->check=0;
        hdr_tcp->check = tcp_v4_check(tcplen, hdr_ip->saddr, hdr_ip->daddr,csum_partial((char*)hdr_tcp, tcplen,0));
        skb->ip_summed = CHECKSUM_NONE; //stop offloading
        hdr_ip->check = 0;
        hdr_ip->check = ip_fast_csum((u8 *)hdr_ip, hdr_ip->ihl);

		return NF_ACCEPT;
	}
	else
	{
		return NF_ACCEPT;
	}
}

