#include "fw_logs_env.h"


void fw_logs_print_logent_report_if_verbose(log_entry_t* ent){
	VPRINT2(KERN_INFO LOGS_TAG "log ent report : src %u,%u dst %u,%u prot %d action %u logr %d count %u",
					ent->src_ip, ent->src_port,
					ent->dst_ip, ent->dst_port,
					ent->protocol,
					ent->action,
					ent->reason,
					ent->count
			);
}

