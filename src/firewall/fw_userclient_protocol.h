
#ifndef SRC_FW_USERCLIENT_PROTOCOL_H_
#define SRC_FW_USERCLIENT_PROTOCOL_H_


// === USER CLIENT 'PROTOCOL'
// --- basic formats, commands and globals agreed upon with user client program


#define USR_SYSFS_STORE_RETVAL_ERR -1


#define USR_SYSFS_RULES_ACTIVE_FORMAT	"%1u"	// single(!) digit, 0 or 1
#define USR_SYSFS_RULES_SIZE_FORMAT		"%u"	// number

#define USR_SYSFS_LOG_SIZE_FORMAT		"%u"	// number
#define USR_SYSFS_LOG_CLEAR_FORMAT		"%1c"	// single(!) char, any


#define USR_SYSFS_CONTAB_CMD_UPDATE_PC 	'U'
#define USR_SYSFS_CONTAB_CMD_ADD 		'A'
#define CON_SEPC " "
#define CON_SEPP 				//"%*[ ]"
#define CON_SEP_EXACT_NEWLINE	"%*[\n]"
#define USR_SYSFS_CONTAB_CON_ENTRY_PARSE_FORMAT	\
						"%1c" CON_SEPP								\
						"%"TOSTR(FW_IP_UINT_MAXLEN)"u" CON_SEPP 	\
						"%"TOSTR(FW_PORT_MAXLEN)"hu" CON_SEPP 		\
						"%"TOSTR(FW_IP_UINT_MAXLEN)"u" CON_SEPP 	\
						"%"TOSTR(FW_PORT_MAXLEN)"hu" CON_SEPP 		\
						"%"TOSTR(FW_PORT_MAXLEN)"hu" CON_SEPP 		\
						CON_SEP_EXACT_NEWLINE

#define CON_SCANF_OK_RETVAL		(6)



#define USER_CD_RULES_RESET_CMD			"$clear_rules$"
#define USER_CD_RULES_RESET_CMD_LEN		13





#endif /* SRC_FW_USERCLIENT_PROTOCOL_H_ */
