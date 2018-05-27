

#ifndef SRC_FW_LOGS_H_
#define SRC_FW_LOGS_H_


#include "fw_logs_env.h"

// Supporting Data Structs
#include "fw_logs_datastruct_filo_circarray.h"


int fw_logs_init(void);
int fw_logs_destroy(void);


int fw_logs_update_entry_to_logs(log_entry_t* ent);
int fw_logs_compare_entries(log_entry_t* ent1, log_entry_t* ent2);

int fw_logs_get_all_as_string(char* const buf, int* len);
int fw_logs_linestr_from_entry(log_entry_t* entry, char* buf, int buf_len, int* nbytes_written);

unsigned int fw_logs_getNumOfEntries(void);
void fw_logs_clearAll(void);



#endif /* SRC_FW_LOGS_H_ */
