

#ifndef SRC_NET_NETFILTER_HANDLER_H_
#define SRC_NET_NETFILTER_HANDLER_H_

#include <linux/netfilter.h>		// API to handle examine packets
#include <linux/netfilter_ipv4.h>	// Provides hook functions for ipv4 ('inspection points') */
#include "env_kernel.h"

// Firewall traffic manager
#include "fw_traffic_man.h"


unsigned int nf_hook_func_fw_decider(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *));

int nf_init_hooks(void);

void nf_destroy_hooks(void);


unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, int (*okfn)(struct sk_buff *));


#endif /* SRC_NET_NETFILTER_HANDLER_H_ */
