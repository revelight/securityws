

#ifndef SRC_FW_FILTER_IDS_H_
#define SRC_FW_FILTER_IDS_H_


#include "fw_standards.h"
#include "fw_rules.h"
#include "fw_logs.h"

#define IDS_TAG "__ids - "


verdict_t fw_filter_ids_decide_packet(packet_ent_t* pac, struct sk_buff *skb);


#endif /* SRC_FW_FILTER_IDS_H_ */
