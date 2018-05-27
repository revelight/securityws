
#include "fw_filter_stateless.h"


// 					 Stateless filter suite
// 				single packet, rule based filters
// ==================================================================




// 						create / destroy
// ===================================================================

int fw_filter_stateless_init(void){
	fw_rules_init();
	return RETVAL_OK;
}

int fw_filter_stateless_destroy(void){
	fw_rules_destroy();
	return RETVAL_OK;
}

// ===================================================================






// 						filter - main
// ===================================================================

verdict_t fw_filter_stateless_decide_packet(packet_ent_t* pac){

	// rules
	VPRINT3(KERN_INFO STATELESS_TAG "checking in rules.. ");
	int applying_rule_idx = -1;
	rule_entry_t* applying_rule = NULL;

	fw_rules_find_applying_rule_for_packet(pac, &applying_rule, &applying_rule_idx);

	// case : matching rule found
	if (applying_rule != NULL && applying_rule_idx>=0) {
		VPRINT3(KERN_CONT "->rule_found!");
		pac->log_reason = applying_rule_idx;
		return (verdict_t)applying_rule->action;
	}

	// case: no match - return stateless default
	VPRINT3(KERN_CONT "->rule_not_found.");
	pac->log_reason = REASON_NO_MATCHING_RULE;
	return FILTER_STATELESS_VERDICT_DEFAULT;

}

// ===================================================================





// 					filter services - hardcoded rule
// ===================================================================

static rule_entry_t loopback_rule = { 			// rule preceding rule table, not logged
		.rule_name 			= "loopback",
		.direction 			= DIRECTION_ANY,
		.src_ip 			= ntohl(IP_LOCALHOST_RANGE_NET),
		.src_prefix_mask 	= ntohl(MASK_8BIT_NET),
		.src_pfs 			= 8,
		.dst_ip				= ntohl(IP_LOCALHOST_RANGE_NET),
		.dst_prefix_mask	= ntohl(MASK_8BIT_NET),
		.dst_pfs			= 8,
		.src_port			= PORT_ANY,
		.dst_port			= PORT_ANY,
		.protocol			= PROT_ANY,
		.ack				= ACK_ANY,
		.action				= NF_ACCEPT,
};


verdict_t fw_filter_stateless_check_hardcoded_preliminary(packet_ent_t* pac){

	VPRINT4(KERN_INFO STATELESS_TAG "checking in hardcoded (loopback)--");

	if (fw_rules_compare_packet_by_appliance(pac, &loopback_rule)==0){
		return VERDICT_ACCEPT; // loopback 127.0.0.0/8 - accept, do not log
	}

	return VERDICT_NONE;

}

// ===================================================================




