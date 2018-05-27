

#ifndef SRC_FW_FILTER_STATEFUL_H_
#define SRC_FW_FILTER_STATEFUL_H_


#include "fw_standards.h"
#include "fw_logs.h"
#include "fw_rules.h"
#include "fw_filter_stateless.h"
#include "fw_conntable.h"


#define STATEFUL_TAG "__stateful -   "



#define HOST_PORT_HTTP 80
#define HOST_PORT_FTP_CTRL 21
#define HOST_PORT_FTP_DATA 20
#define HOST_PORT_SMTP 25
#define HOST_PORT_STRUTSREST 8080

#define PROXY_PORT_HTTP 8001
#define PROXY_PORT_FTP_CTRL 2001
#define PROXY_PORT_FTP_DATA 2000
#define PROXY_PORT_SMTP 2500
#define PROXY_PORT_STRUTSREST 8081

// localhost ip 127.0.0.1  16777343
#define PROXY_IP_NETORDER 16777343

// direction IN : eth1 ip 10.1.1.3
// direction OUT : eth2 ip 10.1.2.3
#define PROXY_FW_IP_FOR_DIR_IN_NETORDER 50397450
#define PROXY_FW_IP_FOR_DIR_OUT_NETORDER 50462986




// ===================================================================


typedef enum {
	// note similar in tcp_states.h
	// Note: these are from pipe perspective, not hosts,
	// meaning what the pipe expects

	FW_TCP_PENDING_CONNECTION = 0,

	FW_TCP_OPEN_SYN_SENT,
	FW_TCP_OPEN_WAITING_SYN_ACK,
	FW_TCP_OPEN_WAITING_ACK,
	FW_TCP_OPEN_SYNACK_SENT,

	FW_TCP_ESTABLISHED,

	FW_TCP_CLOSE_FIN_SENT,
	FW_TCP_CLOSE_WAITING_ACK,
	FW_TCP_CLOSE_FIN_ACKED,
	FW_TCP_CLOSE_WAITING_FIN,
	FW_TCP_CLOSE_WAITING_ACK2,
	FW_TCP_CLOSE_FIN2_SENT,

	FW_TCP_CLOSED_CONNECTION,

} tcp_chain;

// ===================================================================



int fw_filter_stateful_init(void);
int fw_filter_stateful_destroy(void);

verdict_t fw_filter_stateful_decide_packet(
		packet_ent_t* pac,
		struct sk_buff *skb,  unsigned int hooknum);

verdict_t fw_filter_stateful_h_verdict_TCP(
		packet_ent_t* pac, struct sk_buff *skb, unsigned int hooknum);

verdict_t fw_filter_stateful_h_verdict_TCP_FSM(
		con_entry_t* con,
		CON_COL src_col, CON_COL dst_col,
		struct tcphdr* hdr_tcp);


int fw_filter_stateful_h_update_TCP_connection_from_str_cmd(const char *buf, size_t count);


int fw_filter_stateful_h_fake_for_proxy(packet_ent_t* pac, con_entry_t* con,
		struct sk_buff *skb, unsigned int hooknum,
		CON_COL src_col, CON_COL dst_col);

int fw_filter_stateful_h_add_new_TCP_con(packet_ent_t* pac, con_entry_t** res_con);

#endif /* SRC_FW_FILTER_STATEFUL_H_ */
