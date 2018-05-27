

#ifndef SRC_FW_RULES_H_
#define SRC_FW_RULES_H_


#include "fw_standards.h"
#include "fw_userclient_protocol.h" //todo


#define RULES_TAG "_______rules - "
#define RULES_CMD_TAG "_cmd: rules - "




// rule table limits
#define RULES_ENTRIES_MAX 50

// .. string totals
#define RULES_STR_LINE_LOOSE_MAXLEN 100	// based on fw std type string lengths
#define RULES_TOTALSTRING_MAXLEN (RULES_ENTRIES_MAX*RULES_STR_LINE_LOOSE_MAXLEN)


// rule data object
typedef struct {
	char 		rule_name[FW_NAME_MAXLEN];		// names will be no longer than 20 chars
	direction_t direction;
	__be32		src_ip;
	__be32		src_prefix_mask; 	// e.g., 255.255.255.0 as int "in the local endianness" == host
	__u8    	src_pfs; 			// prefix size valid values: 0-32, e.g., /24 for the example above
									// (the field is redundant - easier to print)
	__be32		dst_ip;
	__be32		dst_prefix_mask; 	// as above
	__u8    	dst_pfs; 			// as above
	__u8		protocol; 			// values from: prot_t
	__be16		src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
	__be16		dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023
	ack_t		ack; 				// values from: ack_t
	__u8		action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_entry_t;


// rule strings

// note: "%n" returns the number of characters read so far.
// 		 No input is consumed. Does not increment the assignment count
// note: * means not for storage in var
// note: [\n] - https://stackoverflow.com/questions/35255891/why-wont-this-scanf-format-string-work-n-n
// note: hh=unsigned char* , h=unsigned short*

#define RULES_INT_MAXLEN 		10

#define RL_SEPC 				" "
#define RL_SEPP 				" " //"%*[ ]"
#define RL_SEPC_NEWLINE			"\n"
#define RL_SEP_EXACT_NEWLINE	"%*[\n]"
#define RL_SCANF_OK_RETVAL		(11)


#define RULES_LINE_READ_STR_FORMAT 	\
				"%"TOSTR(FW_NAME_MAXLEN)"s" RL_SEPP 		\
				"%"TOSTR(FW_DIR_MAXLEN)"hhu" RL_SEPP 		\
															\
				"%"TOSTR(FW_IP_UINT_MAXLEN)"u" RL_SEPP 		\
				"%"TOSTR(FW_PFS_MAXLEN)"hhu" RL_SEPP 		\
															\
				"%"TOSTR(FW_IP_UINT_MAXLEN)"u" RL_SEPP 		\
				"%"TOSTR(FW_PFS_MAXLEN)"hhu" RL_SEPP 		\
															\
				"%"TOSTR(FW_PROT_MAXLEN)"hhu" RL_SEPP 		\
															\
				"%"TOSTR(FW_PORT_MAXLEN)"hu" RL_SEPP 		\
				"%"TOSTR(FW_PORT_MAXLEN)"hu" RL_SEPP 		\
															\
				"%"TOSTR(FW_ACK_MAXLEN)"hhu" RL_SEPP 		\
				"%"TOSTR(FW_ACTION_MAXLEN)"hhu"				\
															\
				RL_SEP_EXACT_NEWLINE						\
				"%n"


#define RULES_LINE_PRINT_STR_FORMAT 						\
				"%""s" RL_SEPC 								\
				"%""u" RL_SEPC 								\
															\
				"%""u" RL_SEPC 								\
				"%""u" RL_SEPC 								\
															\
				"%""u" RL_SEPC 								\
				"%""u" RL_SEPC 								\
															\
				"%""u" RL_SEPC 								\
															\
				"%""u" RL_SEPC 								\
				"%""u" RL_SEPC 								\
															\
				"%""u" RL_SEPC 								\
				"%""u" RL_SEPC	 							\
															\
				RL_SEPC_NEWLINE								\
				"%n"





int fw_rules_init(void);
int fw_rules_destroy(void);


int fw_rules_reset(void);
unsigned int fw_rules_getNumOfEntries(void);
int fw_rules_find_applying_rule_for_packet(packet_ent_t* pac, rule_entry_t** rule_applying, int* idx);

int fw_rules_compare_packet_by_appliance(packet_ent_t* pac, rule_entry_t* ent_rule);
//int compareRuleEntries(rule_entry_t* ent1, rule_entry_t* ent2);

int fw_rules_get_as_string(char* buf, int* len);
int fw_rules_linestr_from_entry(rule_entry_t* entry, char* buf, int buf_len, int* nbytes_written);

int fw_rules_add_from_str(char* str, int len);
int fw_rules_insert_rule_from_line(char* line, int* nbytes_read);

unsigned int getNetmaskIntFromPfsize(int pfs);



#endif /* SRC_FW_RULES_H_ */

