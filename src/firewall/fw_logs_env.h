

#ifndef SRC_FW_LOGS_ENV_H_
#define SRC_FW_LOGS_ENV_H_


#include "fw_standards.h"


#define LOGS_TAG "__logs       - "


// Log Data
#define LOGS_ENTRIES_MAX 1000

// Log data object
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	hooknum;      	// as received from netfilter hook
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_entry_t;


// log strings
#define LOGS_LINE_LOOSE_MAXLEN 150
#define LOGS_TOTALSTRING_MAXLEN (LOGS_ENTRIES_MAX*LOGS_LINE_LOOSE_MAXLEN)


#define LG_SEPC 			" "
#define LG_SEPC_NEWLINE		"\n"

#define LOGS_LINE_PRINT_STR_FORMAT \
				"%lu" LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%u" 	LG_SEPC		\
				"%d" 	LG_SEPC		\
				"%u"				\
				LG_SEPC_NEWLINE		\
				"%n"



void fw_logs_print_logent_report_if_verbose(log_entry_t* ent);



#endif /* SRC_FW_LOGS_ENV_H_ */
