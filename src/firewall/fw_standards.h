

#ifndef SRC_FW_STANDARDS_H_
#define SRC_FW_STANDARDS_H_

// === Program Tools
#include "env_program.h"


#include <linux/netfilter.h>		// API to handle examine packets
#include <linux/netfilter_ipv4.h>	// Provides hook functions for ipv4 ('inspection points') */
#include <linux/ip.h>				//
#include <linux/tcp.h>				//
#include <net/tcp.h>				//
#include <linux/udp.h>				//
#include <linux/icmp.h>				//
#include <linux/time.h>

// === FIREWALL STANDARDS


#define FW_IP_VERSION 4

// the protocols we will work with
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


typedef enum {
	DROP	= NF_DROP,
	ACCEPT 	= NF_ACCEPT,
} action_t;


typedef enum {
	VERDICT_DROP					= DROP,
	VERDICT_ACCEPT					= ACCEPT,
	VERDICT_INVALID_LIMIT_LOWER 	= -1,		// values above are valid filtering decisions
	VERDICT_NONE					= -2,
	VERDICT_ERROR					= -3,
} verdict_t;



typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;


typedef enum { // other (non-rule number) reasons to be registered in each log entry
	// ! set only negatives
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -3,
	REASON_CONNTABLE_TCP 	     = -4,
	REASON_ANOMALY_CASE    		 = -5,
	REASON_NO_MATCHING_FILTER	 = -6,
	REASON_ILLEGAL_LIMIT         = -7,	// values above are valid reasons
	REASON_INTERNAL_NONE		 = -25,
	REASON_INTERNAL_DONT_LOG	 = -27,
	REASON_INTERNAL_ERROR		 = -30,
} reason_t;


#define PORT_MAX_NUMERIC_LIMIT 65535
#define PORT_NUMBER_MAX_LEN 5   // 16-bit unsigned short 2^16-1 => 0-65535
typedef enum {
	PORT_ANY		= 0,
	PORT_ABOVE_1023	= 1023,
} port_t;


// net devices configuration
typedef enum netdev_t {
	LOOPBACK,
	OUTSIDE_NET,
	INSIDE_NET,
} NETDEV;

#define LOOPBACK_NET_DEVICE_NAME			"lo"	// this is us
#define OUTSIDE_NETWORK_NET_DEVICE_NAME		"eth1" 	// evil lurks there
#define INSIDE_NETWORK_NET_DEVICE_NAME		"eth2" 	// safe and happy



// basic uniform packet description for filtering
typedef struct {
	direction_t 	direction;
	__be32			src_ip;
	__be16			src_port;
	__be32			dst_ip;
	__be16			dst_port;
	__u8			protocol;
	ack_t			ack;
	unsigned long  	timestamp;
	reason_t     	log_reason;
} packet_ent_t;



// string consts
// type fields - string limits
#define FW_NAME_MAXLEN 		20
#define FW_DIR_MAXLEN		1
#define FW_IP_UINT_MAXLEN 	10
#define FW_PFS_MAXLEN		2
#define FW_PROT_MAXLEN		3
#define FW_PORT_MAXLEN		5
#define FW_ACK_MAXLEN		1
#define FW_ACTION_MAXLEN	1



// === end : FIREWALL STANDARDS


// functions
void fw_standards_print_pac_report_if_verbose(char* tag, packet_ent_t* pac);

#endif /* SRC_FW_STANDARDS_H_ */
