

#ifndef SRC_FW_CONNTABLE_H_
#define SRC_FW_CONNTABLE_H_


#include "fw_standards.h"


#define CONS_TAG "_____conntable - "


#define CONS_TTL_SECS 90
#define CONS_CLOSED_TTL 10	// must be smaller than TTL

typedef enum{
	CON_KEYCOLS_CS_SC,
	CON_KEYCOLS_PROXY_SRC,
	CON_KEYCOLS_NONE,
} CON_KEYCOLS;


typedef enum{
	CON_COL_C 	= 0,	// ip and port
	CON_COL_S	= 1,	// ip and port
	CON_COL_PS	= 2,	// port only
	CON_COL_PC	= 3,	// port only
} CON_COL;



// a 2-way connection entry
// between sides: A <--> B
// use indexes: A->B is 0 , B->A is 1
typedef struct {
	__be32   			ip_c_s[2];
	__be16 				port_c_s_ps_pc[4];
	int  				state_c_s_ps_pc[4];
	unsigned long  		timestamp;
	struct list_head 	lstnode;		// implementing kernel list
} con_entry_t;


// conn strings
#define CONS_ENTRIES_MAX 1000
#define CONS_LINE_LOOSE_MAXLEN 150
#define CONS_TOTALSTRING_MAXLEN (CONS_ENTRIES_MAX*CONS_LINE_LOOSE_MAXLEN)

#define CONS_SEPC 			" "
#define CONS_SEPC_NEWLINE	"\n"

// c_ip, c_port, s_ip, s_port, link-states: c, s
// ps_port, pc_port, link-states: ps, pc , timestamp
#define CONS_LINE_PRINT_STR_FORMAT \
				"%u" 	CONS_SEPC		\
				"%u" 	CONS_SEPC		\
				"%u" 	CONS_SEPC		\
				"%u" 	CONS_SEPC		\
				"%d" 	CONS_SEPC		\
				"%d" 	CONS_SEPC		\
				"%d" 	CONS_SEPC		\
				"%d" 	CONS_SEPC		\
				"%u" 	CONS_SEPC		\
				"%u" 	CONS_SEPC		\
				"%lu" 	CONS_SEPC		\
				CONS_SEPC_NEWLINE		\
				"%n"





int fw_cons_init(void);
int fw_cons_destroy(void);
void fw_cons_clear_all(void);


/*
int fw_cons_compare_packet_entry_to_connection(packet_ent_t* pac,
		con_entry_t* conn, int* match_col);
int fw_cons_find_applying_entry_for_packet(packet_ent_t* pac,
		con_entry_t** ent_found, int* ent_side);
*/

int fw_cons_compare_packet_entry_to_connection_by_cols(
		packet_ent_t* pac, con_entry_t* conn, CON_KEYCOLS keycols,
		CON_COL* match_src_col);


int fw_cons_find_applying_entry_for_packet_by_cols(
		packet_ent_t* pac, CON_KEYCOLS keycols,
		con_entry_t** con_found, CON_COL* match_src_col);



int fw_cons_add_con(packet_ent_t* pac, con_entry_t** result);
int fw_cons_delete_con(con_entry_t* con);
int fw_cons_clear_timeouts(void);

int fw_cons_get_all_as_string(char* const buf, int* len);
int fw_cons_linestr_from_entry(con_entry_t* entry, char* buf, int buf_len, int* nbytes_written);












#endif /* SRC_FW_CONNTABLE_H_ */
