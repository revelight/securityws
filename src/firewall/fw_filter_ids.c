
#include "fw_filter_ids.h"


//  IDS - Intrusion Detection System


// 						filtering - main
// ===================================================================

verdict_t fw_filter_ids_decide_packet(packet_ent_t* pac, struct sk_buff *skb){

	VPRINT4(KERN_INFO IDS_TAG "deciding packet..");

	//  -- Christmas Tree Packet
	struct iphdr* hdr_ip = ip_hdr(skb);
	if (hdr_ip->protocol == PROT_TCP){
		struct tcphdr* hdr_tcp =
				(struct tcphdr*) ((char*)hdr_ip + (hdr_ip->ihl * 4));
		if (hdr_tcp->fin && hdr_tcp->urg && hdr_tcp->psh){
			// xmas packet found!
			VPRINT4(KERN_INFO "--ids module - xmas packet dropped--");
			pac->log_reason = REASON_XMAS_PACKET;
			return VERDICT_DROP;
		}
	}
	return VERDICT_ACCEPT;
}

// ===================================================================
