

#ifndef SRC_FW_TRAFFIC_MAN_H_
#define SRC_FW_TRAFFIC_MAN_H_


#include "fw_standards.h"
#include "fw_filter_stateless.h"
#include "fw_filter_stateful.h"
#include "fw_filter_ids.h"

#define TRAFFICMAN_TAG "_traffic man - "

typedef enum t_fw_state{
	FW_INACTIVE		= 0,
	FW_ACTIVE 		= 1,
	FW_ENUM_LIMIT 	= 2
} FW_STATE;


typedef enum t_fw_dir_type{
	DIR_OK,
	DIR_LOOPBACK,
	DIR_ANOMALY,
	DIR_NONE,
} FW_DIR_TYPE;



// hardcoded rules
#define TFMAN_VERDICT_DEFAULT NF_ACCEPT // default action if no modules decided, should be logged


// == Functions

int fw_traffic_man_init(void);
int fw_traffic_man_destroy(void);
FW_STATE fw_trafficman_getActiveStatus(void);
void fw_trafficman_setActiveStatus(FW_STATE status);



unsigned int fw_trafficman_decidePacket(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *));

int fw_trafficman_packetbreakdown(packet_ent_t* packet_entry, FW_DIR_TYPE* dir_type,
		unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out);


int fw_trafficman_log_packet(packet_ent_t* packet_entry, unsigned char verdict, int hooknum);




#endif /* SRC_FW_TRAFFIC_MAN_H_ */
