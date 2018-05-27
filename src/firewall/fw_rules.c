
#include "fw_rules.h"




// 						create / destroy
// ===================================================================

static rule_entry_t rules_table[RULES_ENTRIES_MAX] = {{{0}}};	// rule table
static int nrules = 0;											// numof rules in table


int fw_rules_init(void){
	return RETVAL_OK;
}

int fw_rules_destroy(void){
	return RETVAL_OK;
}


// ===================================================================



// 					list queries and control
// ===================================================================
int fw_rules_reset(void){
	VPRINT2(KERN_INFO RULES_TAG "reset");
	nrules = 0;
	return RETVAL_OK;
}

unsigned int fw_rules_getNumOfEntries(void){
	return nrules;
}


int fw_rules_find_applying_rule_for_packet(packet_ent_t* pac, rule_entry_t** rule_applying, int* idx){

	// pass rules in order of precedence
	for (int i=0; i<nrules; i++){
		if (fw_rules_compare_packet_by_appliance(pac, &rules_table[i]) == 0){
			*rule_applying = &rules_table[i];
			*idx = i;
			return RETVAL_OK;
		}
	}

	rule_applying = NULL;
	*idx = -1;
	return RETVAL_OK_AND_FAIL;
}

// ===================================================================




// 							comparators
// ===================================================================

// compare entry to a rule by appliance - e.g. check if a filtering rule applies to a a packet entry
int fw_rules_compare_packet_by_appliance(packet_ent_t* pac, rule_entry_t* rule){

	VPRINT4(KERN_INFO RULES_TAG "packet compare:");

	VPRINT4(KERN_CONT "-dir");
	// dir - 01 10 11
	if(	!(pac->direction & rule->direction)) return 1;

	// protocol
	VPRINT4(KERN_CONT "-prot");
	if (rule->protocol != PROT_ANY){
		if (rule->protocol != pac->protocol)
			return 1;
	}

	VPRINT4(KERN_CONT "-ip_src");
	// ip src- mask out irrelevant bits in both ip's, and compare
	if ((pac->src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask)) {
		//printk(KERN_INFO "  rule ip: %u", ent_rule->src_ip);
		//printk(KERN_INFO "rule_mask: %u", ent_rule->src_prefix_mask);
		//printk(KERN_INFO "   ent ip: %u", ent_tested->src_ip);
		return 1;
	}

	VPRINT4(KERN_CONT "-ip_dst");
	// ip src- mask out irrelevant bits in both ip's, and compare
	if ((pac->dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask)) {
		return 1;
	}

	// TCP UDP -only checks - ack and ports
	if (pac->protocol == PROT_TCP || pac->protocol == PROT_UDP) {

		// port src
		VPRINT4(KERN_CONT "-TCP/UDP_port_src");
		if(rule->src_port != 0) { 				// rule port not 'any'
			if (rule->src_port == 1023){  		// rule allows ports >1023
				if (pac->src_port <= 1023)
					return 1;
			} else {								// rule has specific port
				if (pac->src_port != rule->src_port)
					return 1;
			}
		}

		// port dst
		VPRINT4(KERN_CONT "-TCP/UDP_port_dst");
		if(rule->dst_port != 0) { 				// rule port not 'any'
			if (rule->dst_port == 1023){  		// rule allows ports >1023
				if (pac->dst_port <= 1023)
					return 1;
			} else {								// rule has specific port
				if (pac->dst_port != rule->dst_port)
					return 1;
			}
		}
	}

	if (pac->protocol == PROT_TCP){
		VPRINT4(KERN_CONT "-TCP_ack");
		// ack - note: non-tcp packets ack should pref be set as 'any'
		if(	!(pac->ack & rule->ack) ) return 1;
	}


	VPRINT4(KERN_CONT "-rule_match!");
	return 0; // rule applies!

}



/*
// simple value compare - for rule vs. rule comparison - e.g. check if rule exists in table
int compareRuleEntries(rule_entry_t* ent1, rule_entry_t* ent2){

	if(	strcmp(ent1->rule_name, ent2->rule_name)!=0			) return 1;
	if(	ent1->direction 		!=	ent2->direction			) return 1;
	if(	ent1->src_ip 			!=	ent2->src_ip			) return 1;
	if(	ent1->src_prefix_mask 	!=	ent2->src_prefix_mask	) return 1;
	if(	ent1->src_pfs 	!=	ent2->src_pfs	) return 1;
	if(	ent1->dst_ip			!=	ent2->dst_ip			) return 1;
	if(	ent1->dst_prefix_mask	!=	ent2->dst_prefix_mask	) return 1;
	if(	ent1->dst_pfs	!=	ent2->dst_pfs	) return 1;
	if(	ent1->src_port			!=	ent2->src_port			) return 1;
	if(	ent1->dst_port			!=	ent2->dst_port			) return 1;
	if(	ent1->protocol			!=	ent2->protocol			) return 1;
	if(	ent1->ack				!=	ent2->ack				) return 1;
	if(	ent1->action			!=	ent2->action			) return 1;

	return 0; // equal
}

*/


// ===================================================================





// 						string representation
// ===================================================================

int fw_rules_get_as_string(char* const buf, int* len){
	// safechecks
	if (buf==NULL || len==NULL){PERR(ERR, RULES_CMD_TAG "null args"); return RETVAL_ERR;}

	// prep
	buf[0] = '\0';
	int nentries = fw_rules_getNumOfEntries();
	int nchars_written_total = 0;
	int nchars_written_incr  = 0;
	rule_entry_t entry = {{0}};

	// for each entry - write a line
	for (int i=0; i < nentries; i++) {

		// get entry
		entry = rules_table[i];

		// write entry line to buffer
		fw_rules_linestr_from_entry(&entry, buf+nchars_written_total,
				RULES_TOTALSTRING_MAXLEN-nchars_written_total, &nchars_written_incr);

		// update total bytes written
		nchars_written_total += nchars_written_incr;

	}

	printk(KERN_INFO RULES_CMD_TAG "show rules excerpt: %.100s", buf);

	// update result len
	*len = nchars_written_total;
	return RETVAL_OK;
}


int fw_rules_linestr_from_entry(rule_entry_t* entry, char* buf, int buf_len, int* nbytes_written){

	int retval = snprintf(buf, buf_len, RULES_LINE_PRINT_STR_FORMAT,
					entry->rule_name,
					entry->direction,
					entry->src_ip,
					entry->src_pfs,
					entry->dst_ip,
					entry->dst_pfs,
					entry->protocol,
					entry->src_port,
					entry->dst_port,
					entry->ack,
					entry->action,
					nbytes_written // returns num of bytes writen (inc. newline)
					);

	if (retval <= 0){PERR(ERR, "rules line print failed!");return RETVAL_ERR;}
	return RETVAL_OK;
}

// ===================================================================





// 						string to rules
// ===================================================================

int fw_rules_add_from_str(char* str, int len){

	// safechecks
	if (str==NULL){PERR(ERR, RULES_TAG "null args");}

	//printk(KERN_INFO RULES_CMD_TAG "set rules excerpt: %.100s", str);

	// for each line, insert rule
	char* str_idx = str;
	int nbytes_read = 0;
	int nbytes_total = 0;
	int readstatus = RETVAL_OK;

	while (readstatus==RETVAL_OK){
		readstatus = fw_rules_insert_rule_from_line(str_idx, &nbytes_read);

		nbytes_total += nbytes_read;
		str_idx += nbytes_read-1; //todo check why

		if (nbytes_total>=len){
			// str ended
			printk(KERN_INFO RULES_CMD_TAG "set rules from str: str ended");
			break;
		}
	}

	return readstatus;
}


int fw_rules_insert_rule_from_line(char* line, int* nbytes_read){

	rule_entry_t entry = {{0}};

	//printk("line:%.150s\n", line);

	// parse line
	int linescan_retval =
			sscanf(line, RULES_LINE_READ_STR_FORMAT,
					entry.rule_name, 					// char*
					(unsigned char*)&entry.direction,
					&entry.src_ip,
					&entry.src_pfs,
					&entry.dst_ip,
					&entry.dst_pfs,
					&entry.protocol,
					&entry.src_port,
					&entry.dst_port,
					(unsigned char*)&entry.ack,
					&entry.action,
					nbytes_read);	// returns num of bytes read (inc. newline)


	//printk("\nread args:bytes %d:%d\n", linescan_retval, *nbytes_read);

	if (linescan_retval != RL_SCANF_OK_RETVAL) {
		PERR(ERR, RULES_TAG "could not parse line\n");
		return RETVAL_ERR;
	}

	// strictly validate entry values
	if (! (1 <= entry.direction && entry.direction <=3) ) 				{PERR(ERR,"dir"); return RETVAL_ERR;}

	if (! (0 <= entry.src_ip && entry.src_ip <=4294967295) ) 			{PERR(ERR,"ip"); return RETVAL_ERR;}
	if (! (0 <= entry.dst_ip && entry.dst_ip <=4294967295) ) 			{PERR(ERR,"ip"); return RETVAL_ERR;}

	if (! (0 <= entry.src_pfs && entry.src_pfs <=32) )					{PERR(ERR,"pfs"); return RETVAL_ERR;}
	if (! (0 <= entry.dst_pfs && entry.dst_pfs <=32) )					{PERR(ERR,"pfs"); return RETVAL_ERR;}

	if (! (entry.protocol==PROT_ICMP || entry.protocol==PROT_TCP ||
			entry.protocol==PROT_UDP || entry.protocol==PROT_OTHER ||
			entry.protocol==PROT_ANY) ) 								{PERR(ERR,"protocol"); return RETVAL_ERR;}

	if (! (0 <= entry.src_port && entry.src_port <=65535) ) 			{PERR(ERR,"port"); return RETVAL_ERR;}
	if (! (0 <= entry.dst_port && entry.dst_port <=65535) ) 			{PERR(ERR,"port"); return RETVAL_ERR;}

	if (! (1 <= entry.ack && entry.ack <=3) ) 							{PERR(ERR,"ack"); return RETVAL_ERR;}

	if (! (0 <= entry.action && entry.action <=1) ) 					{PERR(ERR,"action"); return RETVAL_ERR;}


	// update prefix masks in host order, from prefix sizes
	entry.src_prefix_mask = ntohl(getNetmaskIntFromPfsize(entry.src_pfs));
	entry.dst_prefix_mask = ntohl(getNetmaskIntFromPfsize(entry.dst_pfs));

	// insert to rules table
	// printk("inserting to rule table line, entry idx: %d\n", nrules); printk("name: %s\n",entry.rule_name);
	if (nrules < RULES_ENTRIES_MAX) {
		rules_table[nrules] = entry; // copy via struct
		nrules++;
	} else {
		return RETVAL_ERR;
	}

	return RETVAL_OK;
}

// ===================================================================



// 							helpers
// ===================================================================

unsigned int getNetmaskIntFromPfsize(int pfs) {
	if (pfs==0)
		return( ~((unsigned int)-1));
	else
		return( ~((1 << (32-pfs)) - 1) );
}
// ===================================================================







