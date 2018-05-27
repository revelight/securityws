
#include "fw_filter_stateful.h"




// 						create / destroy
// ===================================================================

int fw_filter_stateful_init(void){
	fw_filter_stateless_init();
	fw_cons_init();
	return RETVAL_OK;
}

int fw_filter_stateful_destroy(void){
	fw_cons_destroy();
	return RETVAL_OK;
}

// ===================================================================





// 						filtering - main
// ===================================================================

verdict_t fw_filter_stateful_decide_packet(
		packet_ent_t* pac,
		struct sk_buff *skb, unsigned int hooknum){

	VPRINT4(KERN_INFO STATEFUL_TAG "deciding packet..");

	// filter : TCP
	verdict_t verdict = VERDICT_NONE;
	pac->log_reason = REASON_CONNTABLE_TCP;
	verdict = fw_filter_stateful_h_verdict_TCP(pac, skb, hooknum);

	return verdict;
}

// ===================================================================




// 					filtering - protocol flows
// ===================================================================



// main TCP filter
verdict_t fw_filter_stateful_h_verdict_TCP(
		packet_ent_t* pac, struct sk_buff *skb, unsigned int hooknum){

	VPRINT2(KERN_INFO STATEFUL_TAG "TCP flow deciding packet");

	// safety check : TCP only
	if (pac->protocol != PROT_TCP){
		printk(KERN_INFO STATEFUL_TAG "Error, received non-TCP packet - dropping");
		pac->log_reason = REASON_INTERNAL_ERROR;
		return VERDICT_DROP;
	}



	// 				setup : VPRINT report tcp packet
	// ======================================================

	// setup : tcp header pointer
	struct iphdr* hdr_ip = ip_hdr(skb);
	struct tcphdr* hdr_tcp = (struct tcphdr*) ((char*)hdr_ip + (hdr_ip->ihl * 4));

	VPRINT2(KERN_INFO STATEFUL_TAG "incoming packet: src [%u %hu] dst [%u %hu]",
			(pac->src_ip), (pac->src_port),
			(pac->dst_ip), (pac->dst_port) );

	VPRINT2(KERN_CONT "  flags [ s%u a%u f%u r%u ]\n",
			hdr_tcp->syn, hdr_tcp->ack, hdr_tcp->fin, hdr_tcp->rst);

	// ======================================================



	// 			find connection : in con table
	// ======================================================
	// setup : find entry in connection table
	con_entry_t* con = NULL;
	CON_COL src_col = -1;
	CON_KEYCOLS keycols = CON_KEYCOLS_CS_SC; 							// for PRE
	if (hooknum == NF_INET_LOCAL_OUT) keycols = CON_KEYCOLS_PROXY_SRC; 	// for LOCAL_OUT
	fw_cons_find_applying_entry_for_packet_by_cols(pac, keycols, &con, &src_col);
	// ======================================================


	// 			case : connection not in table
	// ======================================================
	if (con == NULL) {
		VPRINT4(KERN_CONT "--con not in table");
		// case : not in table and at LOCAL_OUT - drop
		if (hooknum == NF_INET_LOCAL_OUT){\
			VPRINT2(KERN_CONT "--dropping for local out");
		return VERDICT_DROP;
		}
		// case : not in table and not new connection - drop
		if (!(hdr_tcp->syn==1 && hdr_tcp->ack==0)) return VERDICT_DROP;
		// new connection request - filter against stateless rules
		if (fw_filter_stateless_decide_packet(pac) != VERDICT_ACCEPT)
			return VERDICT_DROP;
		pac->log_reason = REASON_CONNTABLE_TCP; // (stateless updates reason)


		// 			case : valid new connection
		// ----------------------------------------------
		// * add new pending contable entry
		// * tcp fsm logic will later open connection accordingly

		// create new connection in table : updating (C-S)
		fw_filter_stateful_h_add_new_TCP_con(pac ,&con);
		src_col = CON_COL_C; // set src col

	}
	// ======================================================



	// 			setup : working connection pair
	// 		    [connection now present in table]
	// ======================================================

	//VPRINT(KERN_INFO STATEFUL_TAG "connection pair");

	// src-dst working pair will reflect the relevant connection for this packet in the table
	// and the new src or dst for proxy packet re-routing.
	// this logic should remain external to contable logic

	CON_COL dst_col = -1;

	// .. for hook LOCAL OUT : set working dst col according to proxy
	if (src_col==CON_COL_PS) dst_col=CON_COL_C;			// PS-C
	else if (src_col==CON_COL_PC) dst_col=CON_COL_S;	// PC-S

	// .. for hook PRE : set working dst col to PS or PC if needed
	else if (src_col==CON_COL_C)	// C-S or C-PS
		dst_col = (con->port_c_s_ps_pc[CON_COL_PS]!=0) ? CON_COL_PS : CON_COL_S;
	else if (src_col==CON_COL_S)	// S-C or S-PC
		dst_col = (con->port_c_s_ps_pc[CON_COL_PC]!=0) ? CON_COL_PC : CON_COL_C;
	else {
		// error
		printk(KERN_INFO STATEFUL_TAG "TCP flow : Error figuring dst col, dropping");
		return VERDICT_DROP;
	}

	VPRINT2(KERN_INFO STATEFUL_TAG "contable cols: %d,%d", src_col, dst_col);

	// ======================================================



	// 					main filter : TCP FSM
	// ======================================================
	verdict_t verdict = VERDICT_NONE;
	verdict = fw_filter_stateful_h_verdict_TCP_FSM(con, src_col, dst_col, hdr_tcp);
	// ======================================================



	// 			filter verdict and ttl refreshes
	// ======================================================

	// case : packet drop -  not approved by TCP flow
	if (verdict == VERDICT_DROP) {
		// don't refresh ttl
		return VERDICT_DROP;
	}
	// case : closed connection - special ttl
	else if (con->state_c_s_ps_pc[src_col] == FW_TCP_CLOSED_CONNECTION) {
		con->timestamp = pac->timestamp - CONS_TTL_SECS + CONS_CLOSED_TTL;
	}
	// case : packet accepted - refresh con ttl
	else {
		con->timestamp = pac->timestamp;
	}
	// ======================================================



	// 			proxy support : fake and checksum
	// ======================================================
	fw_filter_stateful_h_fake_for_proxy(pac, con, skb, hooknum, src_col, dst_col);
	// ======================================================


	// 			VPRINT report : result and verdict
	// ======================================================
	hdr_ip = ip_hdr(skb);
	hdr_tcp = (struct tcphdr*) ((char*)hdr_ip + (hdr_ip->ihl * 4));
	VPRINT2(KERN_INFO STATEFUL_TAG "resulting packet: src [%u %hu] , dst [%u %hu]",
			ntohl(hdr_ip->saddr), ntohs(hdr_tcp->source),
			ntohl(hdr_ip->daddr), ntohs(hdr_tcp->dest) );
	VPRINT2(KERN_INFO STATEFUL_TAG "verdict: %d", verdict);
	// ======================================================


	// 			packet ready, return verdict
	// ======================================================
	return verdict;
	// ======================================================

}




verdict_t fw_filter_stateful_h_verdict_TCP_FSM(
		con_entry_t* con,
		CON_COL src_col, CON_COL dst_col,
		struct tcphdr* hdr_tcp){

	VPRINT4(KERN_INFO STATEFUL_TAG "main filter : TCP FSM");


	// case : RST immediate termination
	if (hdr_tcp->rst==1) {
		// delete connection --> done by ttl, setting to closed mode
		con->state_c_s_ps_pc[src_col]=FW_TCP_CLOSED_CONNECTION;
		con->state_c_s_ps_pc[dst_col]=FW_TCP_CLOSED_CONNECTION;
		return VERDICT_ACCEPT;
	}

	// cases : progressing TCP states
	switch (con->state_c_s_ps_pc[src_col]) {

	case FW_TCP_ESTABLISHED:  // (most common case)

		// ESTABLISHED : active communication
		if (hdr_tcp->fin!=1){
			return VERDICT_ACCEPT;
		}

		// CLOSE : step 1 : (fin+ack) or (fin)
		else {
			//printk(KERN_INFO STATEFUL_TAG "TCP FLOW: FW_TCP_ESTABLISHED -> receiving fin ->\n FW_TCP_CLOSE_FIN_SENT");
			con->state_c_s_ps_pc[src_col]=FW_TCP_CLOSE_FIN_SENT;
			con->state_c_s_ps_pc[dst_col]=FW_TCP_CLOSE_WAITING_ACK;
			return VERDICT_ACCEPT;
		}

		break;

	case FW_TCP_PENDING_CONNECTION:
		if (hdr_tcp->syn==1 && hdr_tcp->ack==0) {
			con->state_c_s_ps_pc[src_col] = FW_TCP_OPEN_SYN_SENT;
			con->state_c_s_ps_pc[dst_col] = FW_TCP_OPEN_WAITING_SYN_ACK;
			return VERDICT_ACCEPT;
		}
		break;

	case FW_TCP_OPEN_WAITING_SYN_ACK:
		// OPEN : step 2 : (syn+ack)
		if (hdr_tcp->syn==1 && hdr_tcp->ack==1){
			con->state_c_s_ps_pc[src_col]=FW_TCP_OPEN_SYNACK_SENT;
			con->state_c_s_ps_pc[dst_col]=FW_TCP_OPEN_WAITING_ACK;
			return VERDICT_ACCEPT;
		}
		break;

	case FW_TCP_OPEN_WAITING_ACK:
		// OPEN : step 3 : (ack)
		if(hdr_tcp->ack==1){
			con->state_c_s_ps_pc[src_col]=FW_TCP_ESTABLISHED;
			con->state_c_s_ps_pc[dst_col]=FW_TCP_ESTABLISHED;
			return VERDICT_ACCEPT;
		}
		break;

	case FW_TCP_CLOSE_WAITING_ACK:
		// CLOSE : step 2 or 3 : (ack) or (ack+fin)
		if(hdr_tcp->ack==1){
			//printk(KERN_INFO STATEFUL_TAG "TCP FLOW: FW_TCP_CLOSE_WAITING_ACK -> receiving ack=1 ->\n FW_TCP_CLOSE_ACK_SENT or FW_TCP_CLOSE_FIN2_SENT");
			if (hdr_tcp->fin==0){
				// (ack) : continue to stage 2
				con->state_c_s_ps_pc[src_col]=FW_TCP_CLOSE_WAITING_FIN;
				con->state_c_s_ps_pc[dst_col]=FW_TCP_CLOSE_FIN_ACKED;
				return VERDICT_ACCEPT;
			} else {
				// (ack+fin) : jump to stage 3
				con->state_c_s_ps_pc[src_col]=FW_TCP_CLOSE_FIN2_SENT;
				con->state_c_s_ps_pc[dst_col]=FW_TCP_CLOSE_WAITING_ACK2;
				return VERDICT_ACCEPT;
			}
		}
		break;

	case FW_TCP_CLOSE_WAITING_FIN:
		// CLOSE : step 3 : (fin)
		if (hdr_tcp->fin==1) {
			con->state_c_s_ps_pc[src_col]=FW_TCP_CLOSE_FIN2_SENT;
			con->state_c_s_ps_pc[dst_col]=FW_TCP_CLOSE_WAITING_ACK2;
			return VERDICT_ACCEPT;
		}
		break;

	case FW_TCP_CLOSE_WAITING_ACK2:
		// CLOSE : step 4 : (ack)
		if (hdr_tcp->ack==1) {
			//printk(KERN_INFO STATEFUL_TAG "TCP FLOW: FW_TCP_CLOSE_WAITING_ACK2 -> receiving ack=1 ->\n deleting connection");
			// delete connection --> done by ttl, setting to closed mode
			con->state_c_s_ps_pc[src_col]=FW_TCP_CLOSED_CONNECTION;
			con->state_c_s_ps_pc[dst_col]=FW_TCP_CLOSED_CONNECTION;
			return VERDICT_ACCEPT;
		}
		break;

	case FW_TCP_CLOSED_CONNECTION:
		break;

	default:
		break;

	}

	// === any other case ===
	return VERDICT_DROP;				// drop
}

// ===================================================================



// 							helpers
// ===================================================================

int fw_filter_stateful_h_update_TCP_connection_from_str_cmd(const char *buf, size_t count){

	VPRINT4(KERN_INFO STATEFUL_TAG "h_update_TCP_connection_from_str_cmd");

	// --- parse str cmd ---

	char cmd;
	packet_ent_t pac;
	__be16 pc_port;

	int linescan_retval =
			sscanf(buf, USR_SYSFS_CONTAB_CON_ENTRY_PARSE_FORMAT,
					&cmd,
					&pac.src_ip,
					&pac.src_port,
					&pac.dst_ip,
					&pac.dst_port,
					&pc_port
			);

	if (linescan_retval!=CON_SCANF_OK_RETVAL) {
		PERR(ERR, STATEFUL_TAG "storeToUpdateEntry - could not parse line\n");
		return RETVAL_ERR;
	}

	// --- update any other pac fields ---
	// timestamp : will update at writing case


	// --- commit cmd by cases ---

	con_entry_t* con;
	switch (cmd) {

	case USR_SYSFS_CONTAB_CMD_UPDATE_PC:
	{
		CON_COL match_src_col;
		// search for C-S
		fw_cons_find_applying_entry_for_packet_by_cols(&pac, CON_KEYCOLS_CS_SC, &con, &match_src_col);
		// update PC
		con->port_c_s_ps_pc[CON_COL_PC] = pc_port; // pc_port in host order
	}
	break;

	case USR_SYSFS_CONTAB_CMD_ADD:
	{
		// For FTP data - add a pending connection entry (C-S pair)

		// .. set timestamp for packet entry
		struct timeval tv;
		do_gettimeofday(&tv);
		pac.timestamp = tv.tv_sec;

		// .. add new connection
		fw_cons_add_con(&pac, &con);

		// .. setup as pending, with FTP_DATA proxy server
		con->state_c_s_ps_pc[CON_COL_C] = FW_TCP_PENDING_CONNECTION;
		con->state_c_s_ps_pc[CON_COL_S] = FW_TCP_PENDING_CONNECTION;
		con->state_c_s_ps_pc[CON_COL_PS] = FW_TCP_PENDING_CONNECTION;
		con->state_c_s_ps_pc[CON_COL_PC] = FW_TCP_PENDING_CONNECTION;
		con->port_c_s_ps_pc[CON_COL_PS] = PROXY_PORT_FTP_DATA;
		break;
	}

	default:
		PERR(ERR, STATEFUL_TAG "storeToUpdateEntry - could not parse cmd\n");
		return RETVAL_ERR;
		break;
	}
	return RETVAL_OK;
}



int fw_filter_stateful_h_fake_for_proxy(packet_ent_t* pac, con_entry_t* con,
		struct sk_buff *skb, unsigned int hooknum,
		CON_COL src_col, CON_COL dst_col){

	VPRINT2(KERN_INFO STATEFUL_TAG "h_fake_for_proxy : ");

	struct iphdr* hdr_ip = ip_hdr(skb);
	struct tcphdr* hdr_tcp = (struct tcphdr*) ((char*)hdr_ip + (hdr_ip->ihl * 4));

	// --- routing and checksum corrections ---

	// fake dst : C-S to C-PS , S-C to S-PC
	//   don't fake for regular C-S / S-C pairs
	if (dst_col == CON_COL_PS)
	{
		VPRINT2(KERN_CONT "C-S to C-PS");
		// fake dst ip to matching interface ip on packet sub network
		if (pac->direction == DIRECTION_IN) hdr_ip->daddr = PROXY_FW_IP_FOR_DIR_IN_NETORDER;
		else if (pac->direction == DIRECTION_OUT) hdr_ip->daddr = PROXY_FW_IP_FOR_DIR_OUT_NETORDER;
		hdr_tcp->dest = htons(con->port_c_s_ps_pc[dst_col]);
		goto checksum_fix;
	}
	else if (dst_col == CON_COL_PC)
	{
		VPRINT2(KERN_CONT "S-C to S-PC");
		// fake dst ip to matching interface ip on packet sub network
		if (pac->direction == DIRECTION_IN) hdr_ip->daddr = PROXY_FW_IP_FOR_DIR_IN_NETORDER;
		else if (pac->direction == DIRECTION_OUT) hdr_ip->daddr = PROXY_FW_IP_FOR_DIR_OUT_NETORDER;
		hdr_tcp->dest = htons(con->port_c_s_ps_pc[dst_col]);
		goto checksum_fix;
	}

	// fake src : PS-C to S-C , PC-S to C-S
	else if (src_col == CON_COL_PS)
	{
		VPRINT2(KERN_CONT "PS-C to S-C");
		hdr_ip->saddr = htonl(con->ip_c_s[CON_COL_S]);
		hdr_tcp->source = htons(con->port_c_s_ps_pc[CON_COL_S]);
		goto checksum_fix;
	}
	else if (src_col == CON_COL_PC)
	{
		VPRINT2(KERN_CONT "PC-S to C-S");
		hdr_ip->saddr = htonl(con->ip_c_s[CON_COL_C]);
		hdr_tcp->source = htons(con->port_c_s_ps_pc[CON_COL_C]);
		goto checksum_fix;
	}

	VPRINT2(KERN_CONT "normal C-S or S-C");
	goto checksum_done;

	checksum_fix:
	{
		// --- fix of checksum for both IP and TCP ---
		// setup : linearize skb if fragmented and paged
		//   https://stackoverflow.com/questions/23598200/how-to-calculate-tcp-udp-checksum-for-non-linear-skb-payload
		//   https://stackoverflow.com/questions/16610989/calculating-tcp-checksum-in-a-netfilter-module
		//   http://vger.kernel.org/~davem/skb_data.html
		skb_linearize(skb);
		//   now get headers from skb again
		hdr_ip = ip_hdr(skb);
		hdr_tcp = (struct tcphdr*) ((char*)hdr_ip + (hdr_ip->ihl * 4));

		// fix tcp header
		int tcplen = (skb->len - ((hdr_ip->ihl )<< 2));
		hdr_tcp->check = 0; // must zero checksum field when calculating header
		hdr_tcp->check = tcp_v4_check(tcplen, hdr_ip->saddr, hdr_ip->daddr,
				csum_partial((char*)hdr_tcp, tcplen,0));

		// fix ip header
		skb->ip_summed = CHECKSUM_NONE; // stop offloading (checksum being recalculated later)
		hdr_ip->check = 0; // must zero checksum field when calculating header
		hdr_ip->check = ip_fast_csum((u8 *)hdr_ip, hdr_ip->ihl);
	}

	checksum_done:;
	return RETVAL_OK;
}


int fw_filter_stateful_h_add_new_TCP_con(packet_ent_t* pac, con_entry_t** res_con){

	VPRINT1(KERN_CONT STATEFUL_TAG "--creating new con entry");

	// create new connection entry
	con_entry_t* con;
	fw_cons_add_con(pac, &con);		// TODO check failure, also updates timestamp
	con->state_c_s_ps_pc[CON_COL_C] = FW_TCP_PENDING_CONNECTION;
	con->state_c_s_ps_pc[CON_COL_S] = FW_TCP_PENDING_CONNECTION;
	con->state_c_s_ps_pc[CON_COL_PS] = FW_TCP_PENDING_CONNECTION;
	con->state_c_s_ps_pc[CON_COL_PC] = FW_TCP_PENDING_CONNECTION;

	// 		proxy support : also set proxy server (PS) if supported (C-S-PS)
	//            ** ADDITIONAL PROXY SUPPORT CAN BE ADDED HERE ***
	// ------------------------------------------------------------------------
	// * note: packet_entry and contable are both in host order
	switch(pac->dst_port) {
	case HOST_PORT_HTTP:
		con->port_c_s_ps_pc[CON_COL_PS] = PROXY_PORT_HTTP;
		VPRINT1(KERN_CONT "--http");
		break;
	case HOST_PORT_FTP_CTRL:
		con->port_c_s_ps_pc[CON_COL_PS] = PROXY_PORT_FTP_CTRL;
		VPRINT1(KERN_CONT "--ftp ctrl");
		// note: FTP DATA connection should not be created organically
		break;
	case HOST_PORT_SMTP:
		con->port_c_s_ps_pc[CON_COL_PS] = PROXY_PORT_SMTP;
		VPRINT1(KERN_CONT "--smtp %d", HOST_PORT_SMTP);
		break;
	case HOST_PORT_STRUTSREST:
		con->port_c_s_ps_pc[CON_COL_PS] = PROXY_PORT_STRUTSREST;
		VPRINT1(KERN_CONT "--struts %d", HOST_PORT_STRUTSREST);
		break;
	default:
		break;
	}
	// ------------------------------------------------------------------------


	*res_con = con;
	return RETVAL_OK;
}



// ===================================================================

