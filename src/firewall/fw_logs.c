
#include "fw_logs.h"






// 						create / destroy
// ===================================================================

static FiloCircArr logs_table;


int fw_logs_init(void){
	fcr_init(&logs_table);
	VPRINT2(KERN_INFO LOGS_TAG "init [num of logs: %d]\n", fw_logs_getNumOfEntries());
	return RETVAL_OK;
}

int fw_logs_destroy(void){
	// static allocation - not needed
	return RETVAL_OK;
}

// ===================================================================




// 					list queries and control
// ===================================================================


unsigned int fw_logs_getNumOfEntries(void){
	return fcr_getSize(&logs_table);
}


void fw_logs_clearAll(void){
	fcr_init(&logs_table);
}


int fw_logs_update_entry_to_logs(log_entry_t* ent){

	VPRINT3(KERN_INFO LOGS_TAG "update to logs");

	log_entry_t* match = NULL;
	fcr_findMatchItem(&logs_table, ent, fw_logs_compare_entries, &match);

	if (match != NULL) {
		VPRINT3(KERN_CONT " -> match found - update log entry");
		// found a matching log entry
		match->count++;
		match->timestamp = ent->timestamp;

		//fw_logs_print_logent_report_if_verbose(match);
		// move to head of queue
		fcr_popItemAndAdd(&logs_table, match);
		//fw_logs_print_logent_report_if_verbose(match);

	} else {
		// no match - insert as latest
		VPRINT3(KERN_CONT " -> no match - insert new log entry");
		ent->count = 1;
		//fw_logs_print_logent_report_if_verbose(ent);
		fcr_insert(&logs_table, ent);
		//fcr_printQueue(&logs_table); // testing
		//fw_logs_print_logent_report_if_verbose(ent);
	}

	return RETVAL_OK;
}


// ===================================================================





// 							comparators
// ===================================================================

int fw_logs_compare_entries(log_entry_t* ent1, log_entry_t* ent2){

	// note: timestamp field not compared
	if(	ent1->src_ip			!=	ent2->src_ip			) return 1;
	if(	ent1->dst_ip			!=	ent2->dst_ip			) return 1;
	if(	ent1->src_port			!=	ent2->src_port			) return 1;
	if(	ent1->dst_port			!=	ent2->dst_port			) return 1;
	if(	ent1->protocol 			!=	ent2->protocol			) return 1;
	if(	ent1->hooknum 			!=	ent2->hooknum			) return 1;
	if(	ent1->action 			!=	ent2->action			) return 1;
	if(	ent1->reason			!=	ent2->reason			) return 1;
	// note: count field not compared

	return 0;

}
// ===================================================================






// 						string representation
// ===================================================================

int fw_logs_get_all_as_string(char* const buf, int* len){

	VPRINT2(KERN_INFO LOGS_TAG "preparing report..  num of logs: %d\n", fw_logs_getNumOfEntries());

	// safechecks
	if (buf==NULL || len==NULL){PERR(ERR, "null args"); return RETVAL_ERR;}

	// prep
	buf[0] = '\0';
	int nentries = fw_logs_getNumOfEntries();
	int nchars_written_total = 0;
	int nchars_written_incr  = 0;
	log_entry_t* entry = NULL;

	// for each entry - write a line
	for (int i=0; i < nentries; i++) {

		// get entry
		fcr_getItemAtIdx(&logs_table, i, &entry);

		// write entry line to buffer
		fw_logs_linestr_from_entry(entry, buf+nchars_written_total,
				LOGS_TOTALSTRING_MAXLEN-nchars_written_total, &nchars_written_incr);

		// update total bytes written
		nchars_written_total += nchars_written_incr;
	}

	VPRINT2(KERN_INFO LOGS_TAG "excerpt: %.100s", buf);

	// update result len
	*len = nchars_written_total;
	return RETVAL_OK;
}


int fw_logs_linestr_from_entry(log_entry_t* entry, char* buf, int buf_len, int* nbytes_written){

	//fw_logs_print_logent_report_if_verbose(entry);

	int retval = snprintf(buf, buf_len, LOGS_LINE_PRINT_STR_FORMAT,
					entry->timestamp,
					entry->src_ip,
					entry->dst_ip,
					entry->src_port,
					entry->dst_port,
					entry->protocol,
					entry->hooknum,
					entry->action,
					entry->reason,
					entry->count,
					nbytes_written 	// returns num of bytes writen (inc. newline)
					);

	if (retval <= 0) {PERR(ERR, LOGS_TAG "logs line print failed!"); return RETVAL_ERR;}
	return RETVAL_OK;
}

// ===================================================================



