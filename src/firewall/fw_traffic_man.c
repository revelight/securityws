
#include "fw_traffic_man.h"



// 					 Firewall Traffic Manager
// 				 top-most filtering flow manager
// 				 provides basic packet breakdown
// 	   	   uses filter suites : ids, stateless, stateful
// ==================================================================




//	 					create / destroy
// ===================================================================

static FW_STATE fw_state = FW_ACTIVE;

int fw_traffic_man_init(void){
	VPRINT2(KERN_INFO TRAFFICMAN_TAG "init");
	fw_logs_init();
	fw_filter_stateless_init(); 	// also inits rules
	fw_filter_stateful_init();  	// also inits connection table
	return RETVAL_OK;
}

int fw_traffic_man_destroy(void){
	VPRINT4(KERN_INFO TRAFFICMAN_TAG "destroy");
	fw_logs_destroy();
	fw_filter_stateless_destroy(); 	//
	fw_filter_stateful_destroy(); 	// also destroys connection table
	return RETVAL_OK;
}
// ===================================================================



//	 				firewall filtering activation
// ===================================================================

FW_STATE fw_trafficman_getActiveStatus(void){
	return fw_state;
}

void fw_trafficman_setActiveStatus(FW_STATE status){
	fw_state = status;
}
// ===================================================================





//	 					main filtering
// ===================================================================

// topmost filtering logic handler
// Note: currently registered on hooks: PRE, LOCAL_OUT

unsigned int fw_trafficman_decidePacket(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)){

	VPRINT2(KERN_INFO "\n" TRAFFICMAN_TAG "__________________packet decide_________________");


	//	 			  basic packet breakdown
	// ======================================================
	packet_ent_t pac = {0};					// packet analysis
	FW_DIR_TYPE dir_type = DIR_NONE;		// direction analysis
	int verdict = VERDICT_NONE;	 			// filtering verdict

	// breakdown packet for basic filtering : packet entry
	int rv;
	rv = fw_trafficman_packetbreakdown(&pac, &dir_type, hooknum, skb, in, out);
	if (rv == RETVAL_ERR){
		PERR(ERR, TRAFFICMAN_TAG "packet breakdown failed! filtering default");
		return TFMAN_VERDICT_DEFAULT;
	}
	else if (rv == RETVAL_OK_AND_CANT_CONTINUE){
		return VERDICT_ACCEPT;
	}

	fw_standards_print_pac_report_if_verbose(TRAFFICMAN_TAG, &pac);

	// ======================================================



	//	 	filter suite : preliminary configuration based
	// ======================================================


	// filter : fw active mode
	if (fw_state == FW_INACTIVE){
		VPRINT4(KERN_INFO TRAFFICMAN_TAG "accepting packet : fw inactive");
		verdict = NF_ACCEPT;
		pac.log_reason = REASON_FW_INACTIVE;
		fw_trafficman_log_packet(&pac, (unsigned char)verdict, hooknum); // log also when fw inactive
		return verdict;
	}

	// filter : direction anomaly
	if (dir_type == DIR_ANOMALY) {
		VPRINT1(KERN_INFO TRAFFICMAN_TAG "dropping packet : direction anomaly");
		return VERDICT_DROP;
	}

	// filter : loopback
	if (dir_type == DIR_LOOPBACK){
		// loopback check provided as a service by 'stateless' filter
		verdict = fw_filter_stateless_check_hardcoded_preliminary(&pac);

		if (verdict > VERDICT_INVALID_LIMIT_LOWER){
			VPRINT1(KERN_INFO TRAFFICMAN_TAG "loopback packet : verdict %d", verdict);
			return verdict;
		}
	}

	// ======================================================



	//	 		filter suite : fw filtering modules
	// ======================================================

	VPRINT2(KERN_INFO TRAFFICMAN_TAG "filtering modules:");


	if (pac.protocol != PROT_TCP){

		VPRINT4(KERN_INFO TRAFFICMAN_TAG "non-TCP packet");

		// ==== NON-TCP PACKETS ====

		// filter : hooknums for non-TCP, non-loopback
		if (hooknum == NF_INET_LOCAL_OUT || hooknum == NF_INET_LOCAL_IN) {
			VPRINT2(KERN_INFO TRAFFICMAN_TAG "dropping non-TCP packet for hooknum %d", hooknum);
			return VERDICT_DROP; // drop, do not log
		}
		else if (hooknum == NF_INET_PRE_ROUTING) {
			VPRINT2(KERN_INFO TRAFFICMAN_TAG "filtering non-TCP packet for hooknum %d", hooknum);
			// filter : stateless (rules based)
			verdict = fw_filter_stateless_decide_packet(&pac);
		}

	}
	else {

		// ==== TCP PACKETS ====

		VPRINT2(KERN_INFO TRAFFICMAN_TAG "TCP packet");

		// filter : IDS
		verdict = fw_filter_ids_decide_packet(&pac, skb);

		// filter : stateful
		if (verdict == VERDICT_ACCEPT){
			verdict = fw_filter_stateful_decide_packet(&pac, skb, hooknum);
		}
	}

	// ======================================================



	//	 			filter : traffic man default
	// ======================================================
	// note: should not get here in current logic
	if (verdict <= VERDICT_INVALID_LIMIT_LOWER){
		verdict = TFMAN_VERDICT_DEFAULT;
		pac.log_reason = REASON_NO_MATCHING_FILTER;
	}
	// ======================================================



	//	 			result : logging and verdict
	// ======================================================
	fw_trafficman_log_packet(&pac, (unsigned char)verdict, hooknum);

	VPRINT2(KERN_INFO TRAFFICMAN_TAG "________________________________________________\n\n");


	// decision done!
	return (unsigned int)verdict;
	// ======================================================
}


// ===================================================================








//	 						helpers
// ===================================================================

// break down skb to a host rule entry (skb fields all in network order)
int fw_trafficman_packetbreakdown(packet_ent_t* pac, FW_DIR_TYPE* dir_type,
		unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out){

	if (pac == NULL || skb == NULL ) {
		PERR(ERR, TRAFFICMAN_TAG "null args");
		return RETVAL_ERR;
	}


	// --- packet creation timestamp ---
	struct timeval tv;
	do_gettimeofday(&tv);
	pac->timestamp = tv.tv_sec;

	// --- packet log reason ---
	pac->log_reason = REASON_INTERNAL_NONE;


	// --- network - ip src, ip dst, protocol [network header] ---
	struct iphdr* hdr_ip = ip_hdr(skb);
	// filter : not ipv4
	if (hdr_ip->version != FW_IP_VERSION){
		VPRINT4(KERN_INFO TRAFFICMAN_TAG "packet not ipv4");
		return RETVAL_OK_AND_CANT_CONTINUE;
	}

	//printk(KERN_INFO "src ip from skb: %d",hdr_ip->saddr);
	pac->src_ip = ntohl(hdr_ip->saddr);
	pac->dst_ip = ntohl(hdr_ip->daddr);
	pac->protocol = hdr_ip->protocol;
	//printk(KERN_INFO "header untouched ip's: %u, %u",hdr_ip->saddr, hdr_ip->daddr);



	// --- transport - src port, dst port [transport header] ---
	if (hdr_ip->protocol == PROT_ICMP) {
		//struct icmphdr* hdr_icmp = icmp_hdr(skb);
		pac->src_port = PORT_ANY;
		pac->dst_port = PORT_ANY;
		pac->ack = ACK_ANY;

	}
	else if (hdr_ip->protocol == PROT_TCP){
		// [!] special tcp header fix
		struct tcphdr* hdr_tcp =
				(struct tcphdr*) ((char*)hdr_ip + (hdr_ip->ihl * 4));
		//printk(KERN_INFO "tcp header untouched ports: %u, %u",hdr_tcp->source, hdr_tcp->dest);
		pac->src_port = ntohs(hdr_tcp->source);
		pac->dst_port = ntohs(hdr_tcp->dest);
		// TCP ACK
		if (hdr_tcp->ack==0) pac->ack = ACK_NO;
		else if (hdr_tcp->ack==1) pac->ack = ACK_YES;
		else {;}//should not happen

	}
	else if (hdr_ip->protocol == PROT_UDP){
		struct udphdr* hdr_udp = udp_hdr(skb);
		pac->src_port = ntohs(hdr_udp->source);
		pac->dst_port = ntohs(hdr_udp->dest);
		pac->ack = ACK_ANY;

	}
	else { // other protocol
		//sk_buff_data_t* sknetheader =  skb_network_header(skb);
		pac->src_port = PORT_ANY;
		pac->dst_port = PORT_ANY;
		pac->ack = ACK_ANY;
	}


	// --- link - direction ---
	if (in == NULL) {
		if (strcmp(out->name, LOOPBACK_NET_DEVICE_NAME)==0) {
			*dir_type = DIR_LOOPBACK; pac->direction = DIRECTION_OUT;}
		else if (strcmp(out->name, OUTSIDE_NETWORK_NET_DEVICE_NAME)==0) {
			*dir_type = DIR_OK; pac->direction = DIRECTION_OUT;}
		else if (strcmp(out->name, INSIDE_NETWORK_NET_DEVICE_NAME)==0) {
			*dir_type = DIR_OK; pac->direction = DIRECTION_IN;}

	} else if (out == NULL) {
		if (strcmp(in->name, LOOPBACK_NET_DEVICE_NAME)==0) {
			*dir_type = DIR_LOOPBACK; pac->direction = DIRECTION_OUT;}
		else if (strcmp(in->name, OUTSIDE_NETWORK_NET_DEVICE_NAME)==0) {
			*dir_type = DIR_OK; pac->direction = DIRECTION_IN;}
		else if (strcmp(in->name, INSIDE_NETWORK_NET_DEVICE_NAME)==0) {
			*dir_type = DIR_OK; pac->direction = DIRECTION_OUT;}

	} else {
		if ( (strcmp(in->name, INSIDE_NETWORK_NET_DEVICE_NAME)==0)   &&
				(strcmp(out->name, OUTSIDE_NETWORK_NET_DEVICE_NAME)==0) ){
			*dir_type = DIR_OK; pac->direction = DIRECTION_OUT;}
		else if ( (strcmp(in->name, OUTSIDE_NETWORK_NET_DEVICE_NAME)==0)   &&
				(strcmp(out->name, INSIDE_NETWORK_NET_DEVICE_NAME)==0) ){
			*dir_type = DIR_OK; pac->direction = DIRECTION_IN;}

		else {*dir_type = DIR_ANOMALY; pac->direction = DIRECTION_ANY;}
	}


	// == packet entry ready!
	return RETVAL_OK;

}



// prepare log entry from packet entry
int fw_trafficman_log_packet(packet_ent_t* pac, unsigned char verdict, int hooknum){

	VPRINT3(KERN_INFO TRAFFICMAN_TAG "updating to logs..");
	//fw_standards_print_pac_report_if_verbose(TRAFFICMAN_TAG, pac);


	if (pac->log_reason == REASON_INTERNAL_DONT_LOG)
		return RETVAL_OK;

	if (pac->src_ip==0 || pac->dst_ip==0 || pac->protocol==0){
		VPRINT1(KERN_INFO TRAFFICMAN_TAG "anomaly case 000000");
		PERR(ERR, TRAFFICMAN_TAG "** trying to log 0000 pac - revoking, please check **");
		return RETVAL_ERR;
	}

	log_entry_t log;

	log.timestamp = pac->timestamp;
	log.src_ip = pac->src_ip;
	log.dst_ip = pac->dst_ip;
	log.src_port = pac->src_port;
	log.dst_port = pac->dst_port;
	log.protocol = pac->protocol;
	log.hooknum = hooknum;
	log.action = verdict;
	log.reason = pac->log_reason;
	log.count = 1; // not really used


	// log : update logs
	fw_logs_update_entry_to_logs(&log);

	return RETVAL_OK;

}





// ===================================================================

