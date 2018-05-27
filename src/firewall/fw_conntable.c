
#include "fw_conntable.h"




// 						fw connection table
// ===================================================================
static LIST_HEAD(conntable);
// ===================================================================



// 						create / destroy
// ===================================================================
int fw_cons_init(void){
	return RETVAL_OK;
}

int fw_cons_destroy(void){

	con_entry_t* cur;
	con_entry_t* nxt;
	list_for_each_entry_safe(cur, nxt, &conntable, lstnode) {
		list_del(&cur->lstnode);
		kfree(cur);
	}

	return RETVAL_OK;
}


void fw_cons_clear_all(void){
	VPRINT2(KERN_INFO CONS_TAG "reset");
	fw_cons_destroy();
	fw_cons_init();
}


// ===================================================================



// 							comparators
// ===================================================================


int fw_cons_compare_packet_entry_to_connection_by_cols(
		packet_ent_t* pac, con_entry_t* conn, CON_KEYCOLS keycols,
		CON_COL* match_src_col){


	// Searches for C-S or S-C pairs (for PRE)
	if (keycols == CON_KEYCOLS_CS_SC) {
		// case: C-S
		if (pac->src_ip==conn->ip_c_s[CON_COL_C] &&
				pac->src_port==conn->port_c_s_ps_pc[CON_COL_C] &&
				pac->dst_ip==conn->ip_c_s[CON_COL_S] &&
				pac->dst_port==conn->port_c_s_ps_pc[CON_COL_S]){
			*match_src_col = CON_COL_C; // return matching side in connection
			return 0; // return equal
		}

		// case: S-C
		if (pac->src_ip==conn->ip_c_s[CON_COL_S] &&
				pac->src_port==conn->port_c_s_ps_pc[CON_COL_S] &&
				pac->dst_ip==conn->ip_c_s[CON_COL_C] &&
				pac->dst_port==conn->port_c_s_ps_pc[CON_COL_C]){
			*match_src_col = CON_COL_S; // return matching side in connection
			return 0; // return equal
		}
	}


	// Searches by by PS-C or PC-S (for LOCAL_OUT)
	// src: port , dst: ip and port
	if (keycols == CON_KEYCOLS_PROXY_SRC) {

		// case: PS-C
		if (pac->src_port==conn->port_c_s_ps_pc[CON_COL_PS] &&
				pac->dst_ip==conn->ip_c_s[CON_COL_C] &&
				pac->dst_port==conn->port_c_s_ps_pc[CON_COL_C]){
			*match_src_col = CON_COL_PS; // return matching side in connection
			return 0; // return equal
		}

		// case: PC-S
		if (pac->src_port==conn->port_c_s_ps_pc[CON_COL_PC] &&
				pac->dst_ip==conn->ip_c_s[CON_COL_S] &&
				pac->dst_port==conn->port_c_s_ps_pc[CON_COL_S]){
			*match_src_col = CON_COL_PC; // return matching side in connection
			return 0; // return equal
		}

	}

	return 1;

}




// ===================================================================



// 							list helpers
// ===================================================================

// note: mandatory pac fields : src(dst) ip and port, timestamp
int fw_cons_add_con(packet_ent_t* pac, con_entry_t** result){

	con_entry_t* con;
	con = kmalloc(sizeof(*con), GFP_ATOMIC);
	if (con==NULL){PERR(ERR, CONS_TAG "CRITICAL: allocation error"); return RETVAL_ERR;}

	// Update C-S and timestamp from packet

	con->ip_c_s[CON_COL_C] = pac->src_ip;
	con->ip_c_s[CON_COL_S] = pac->dst_ip;
	con->port_c_s_ps_pc[CON_COL_C] = pac->src_port;
	con->port_c_s_ps_pc[CON_COL_S] = pac->dst_port;
	con->timestamp = pac->timestamp;

	// defaults
	con->port_c_s_ps_pc[CON_COL_PS] = 0;
	con->port_c_s_ps_pc[CON_COL_PC] = 0;

	// note! caller must handle states

	INIT_LIST_HEAD(&con->lstnode);

	list_add(&con->lstnode, &conntable);

	*result = con;
	return RETVAL_OK;
}


int fw_cons_delete_con(con_entry_t* con){

	list_del(&con->lstnode);
	kfree(con);

	return RETVAL_OK;
}



int fw_cons_clear_timeouts(void){

	con_entry_t* entry = NULL;
	con_entry_t* next = NULL;

	struct timeval tv;
	do_gettimeofday(&tv);
	unsigned long time_secs = tv.tv_sec;

	list_for_each_entry_safe(entry, next, &conntable, lstnode) {

		// == delete if timeout
		if(entry->timestamp+CONS_TTL_SECS <= time_secs) {
			list_del(&entry->lstnode);
			kfree(entry);
			continue;
		}
	}

	return RETVAL_OK;

}





int fw_cons_find_applying_entry_for_packet_by_cols(
		packet_ent_t* pac, CON_KEYCOLS keycols,
		con_entry_t** con_found, CON_COL* match_src_col){

	con_entry_t* entry = NULL;
	con_entry_t* next = NULL;

	struct timeval tv;
	do_gettimeofday(&tv);
	unsigned long time_secs = tv.tv_sec;

	list_for_each_entry_safe(entry, next, &conntable, lstnode) {

		// == delete entry if timeout
		if(entry->timestamp+CONS_TTL_SECS <= time_secs) {
			list_del(&entry->lstnode);
			kfree(entry);
			continue;
		}

		// == otherwise, check match
		else if (0 == fw_cons_compare_packet_entry_to_connection_by_cols(
				pac, entry, keycols, match_src_col)){
			// entry match found!
			*con_found = entry;
			return RETVAL_OK;
		}
	}
	// entry match not found
	*con_found = NULL;
	*match_src_col = -1;
	return RETVAL_OK_AND_FAIL;
}




// ===================================================================





// 						string representation
// ===================================================================



int fw_cons_get_all_as_string(char* const buf, int* len){

	VPRINT4(KERN_INFO CONS_TAG "preparing connections report..  \n");

	fw_cons_clear_timeouts();

	// safechecks
	if (buf==NULL || len==NULL){PERR(ERR, CONS_TAG "null args"); return RETVAL_ERR;}

	// prep
	buf[0] = '\0';
	int nchars_written_total = 0;
	int nchars_written_incr  = 0;
	con_entry_t* entry = NULL;

	// for each entry - write a line
	list_for_each_entry(entry, &conntable, lstnode) {

		// write entry line to buffer
		fw_cons_linestr_from_entry(entry, buf+nchars_written_total,
				CONS_TOTALSTRING_MAXLEN-nchars_written_total, &nchars_written_incr);

		// update total bytes written
		nchars_written_total += nchars_written_incr;
	}

	VPRINT4(KERN_INFO CONS_TAG "connections report excerpt: %.100s", buf);

	// update result len
	*len = nchars_written_total;
	return RETVAL_OK;
}




int fw_cons_linestr_from_entry(con_entry_t* entry, char* buf,
		int buf_len, int* nbytes_written){

	//printk("connections line print: for entry: src ip %u", entry->ab_ip[0]);

	int retval = snprintf(buf, buf_len, CONS_LINE_PRINT_STR_FORMAT,
			entry->ip_c_s[CON_COL_C],
			entry->port_c_s_ps_pc[CON_COL_C],
			entry->ip_c_s[CON_COL_S],
			entry->port_c_s_ps_pc[CON_COL_S],
			entry->state_c_s_ps_pc[CON_COL_C],
			entry->state_c_s_ps_pc[CON_COL_S],

			entry->state_c_s_ps_pc[CON_COL_PS],
			entry->state_c_s_ps_pc[CON_COL_PC],

			entry->port_c_s_ps_pc[CON_COL_PS],
			entry->port_c_s_ps_pc[CON_COL_PC],

			entry->timestamp,
			nbytes_written 	// returns num of bytes writen (inc. newline)
	);

	if (retval <= 0) {PERR(ERR, CONS_TAG "connections line print failed!"); return RETVAL_ERR;}
	return RETVAL_OK;

}



// ===================================================================



