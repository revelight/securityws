

#ifndef SRC_FW_LOGS_DATASTRUCT_FILO_CIRCARRAY_H_
#define SRC_FW_LOGS_DATASTRUCT_FILO_CIRCARRAY_H_


// Simple static implementation of LOGS TABLE
// -- Modified circular array FILO
// -- loosely based on code: <http://www.xappsoftware.com/wordpress/2012/09/27/a-simple-implementation-of-a-circular-queue-in-c-language/>

#include "env_program.h"
#include "fw_logs_env.h"

#define FCR_SIZE LOGS_ENTRIES_MAX			// max num of items todo - move from logs to logs globals scheme
#define FCR_ITEM log_entry_t				// apply a --struct-- to be the queue's data type

typedef struct t_fcr_item{
	int val;
} FcrItem;

typedef struct circularQueue_s{
	int     	head;					// head index
	int     	tail;					// tail index
	int     	nvalids;				// num valid items
	FCR_ITEM   data[FCR_SIZE];			// the data array
} FiloCircArr;



void fcr_init(FiloCircArr *q);
int fcr_getSize(FiloCircArr *q);
int fcr_isEmpty(FiloCircArr *q);
int fcr_insert(FiloCircArr *q, FCR_ITEM* item);
int fcr_deleteItem(FiloCircArr *q, FCR_ITEM* item);
int fcr_popItemAndAdd(FiloCircArr *q, FCR_ITEM* item);

int fcr_getItemAtIdx(FiloCircArr *q, int idx, FCR_ITEM** item);

int fcr_findMatchItem(FiloCircArr* q, FCR_ITEM* item,
int (*comparator)(FCR_ITEM*, FCR_ITEM*), FCR_ITEM** result);
int fcr_isItemInFcr(FiloCircArr *q, FCR_ITEM* item);
void fcr_printQueue(FiloCircArr *q);





#endif /* SRC_FW_LOGS_DATASTRUCT_FILO_CIRCARRAY_H_ */
