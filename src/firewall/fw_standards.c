

#include "fw_standards.h"


void fw_standards_print_pac_report_if_verbose(char* tag, packet_ent_t* pac){
	VPRINT2(KERN_INFO "%spac report: dir %d src %u,%u dst %u,%u prot %d logr %d",
			tag,
			pac->direction,
			pac->src_ip, pac->src_port,
			pac->dst_ip, pac->dst_port,
			pac->protocol,
			pac->log_reason
	);
}
