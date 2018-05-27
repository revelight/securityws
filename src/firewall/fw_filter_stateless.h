

#ifndef SRC_FW_FILTER_STATELESS_H_
#define SRC_FW_FILTER_STATELESS_H_

#include "fw_standards.h"
#include "fw_rules.h"
#include "fw_logs.h"


#define STATELESS_TAG "___stateless - "

#define FILTER_STATELESS_VERDICT_DEFAULT VERDICT_ACCEPT
// note : stateful module will only init cons with VERDICT_ACCEPT


// network consts
#define IP_LOCALHOST_RANGE_NET 	127			// 127.0.0.0
#define MASK_8BIT_NET 			255			// 255.0.0.0
#define MASK_24BIT_NET 			16777215	// 255.255.255.0



// Functions

int fw_filter_stateless_init(void);
int fw_filter_stateless_destroy(void);

verdict_t fw_filter_stateless_check_hardcoded_preliminary(packet_ent_t* pac);
verdict_t fw_filter_stateless_decide_packet(packet_ent_t* pac);


#endif /* SRC_FW_FILTER_STATELESS_H_ */
