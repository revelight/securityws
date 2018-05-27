
#include "fw_logs_datastruct_filo_circarray.h"



void fcr_init(FiloCircArr *q){
	q->nvalids =  0;
	q->head    =  0;
	q->tail    =  0;
	// consider: also zero all data values (inefficient for large data)
	return;
}


int fcr_isEmpty(FiloCircArr *q){
	if(q->nvalids==0){
		//printf("i'm empty\n");
		return(1);
	}
	else
		return(0);
}


int fcr_getSize(FiloCircArr *q){
	return q->nvalids;
}


int fcr_insert(FiloCircArr *q, FCR_ITEM* item){

	VPRINT4(KERN_INFO LOGS_TAG "fcr insert ");

	if (!fcr_isEmpty(q)) // if empty: h=t=new
		q->tail = (q->tail+1)%FCR_SIZE; // if not empty: t++

	q->data[q->tail] = *item; // via struct copy

	if (q->nvalids >= FCR_SIZE) // was full
		q->head = (q->head+1)%FCR_SIZE; // head was overwritten
	else
		q->nvalids++;

	return 0;
}


int fcr_deleteItem(FiloCircArr *q, FCR_ITEM* item){

	VPRINT4(KERN_INFO LOGS_TAG "fcr delete");

	// case : q illegal or empty
	if (item==NULL || fcr_isEmpty(q))
		return RETVAL_ERR;

	// case : q size 1 (h==t)
	if (q->nvalids==1){
		q->nvalids--;
		return RETVAL_OK; // no tail change
	}

	// main case : q size >1
	{
		// .. set num of swaps
		int swaps_cnt = &(q->data[q->tail]) - item;
		if(swaps_cnt < 0) swaps_cnt = FCR_SIZE + swaps_cnt; // case : tail before item

		// .. do swaps
		FCR_ITEM* cur = item;
		while(swaps_cnt>0) {
			if (cur == &q->data[FCR_SIZE-1]) { 	// case : swap across array bounds
				*cur = q->data[0];
				cur = &q->data[0];
			} else {							// case : normal swap
				*cur = *(cur+1);
				cur++;
			}
			swaps_cnt--;
		}

		// .. update tail and nvalids
		q->tail = (q->tail-1 + FCR_SIZE)%FCR_SIZE;
		q->nvalids--;

		return RETVAL_OK;
	}

}


int fcr_popItemAndAdd(FiloCircArr *q, FCR_ITEM* item){
	// copy item, delete it, then add it.
	FCR_ITEM sto = *item;
	//fcr_printQueue(q); // testing
	fcr_deleteItem(q, item);
	//fcr_printQueue(q); // testing
	fcr_insert(q, &sto);
	//fcr_printQueue(q); // testing
	return RETVAL_OK;
}


int fcr_isItemInFcr(FiloCircArr *q, FCR_ITEM* item){

	if (q->tail-q->head >= 0){
		if (&q->data[q->head] <= item && item <= &q->data[q->tail])
			return 1;
	}
	else if ( (&q->data[0] <= item && item <= &q->data[q->tail])
			|| (&q->data[q->head] <= item && item <= &q->data[FCR_SIZE-1]) )
		return 1;

	return 0;

}


int fcr_getItemAtIdx(FiloCircArr *q, int idx, FCR_ITEM** item){

	if (idx < 0 || q->nvalids <= idx) {
		PERR(ERR, LOGS_TAG "fcrGetItemAtIdx illegal index!");
		*item = NULL;
		return -1;
	}

	*item = &(q->data[( (q->head)+idx ) %FCR_SIZE]);

	return 0;
}



int fcr_findMatchItem(FiloCircArr* q, FCR_ITEM* item,
		int (*comparator)(FCR_ITEM*, FCR_ITEM*), FCR_ITEM** result){

	int cur = q->head;
	int cnt = q->nvalids;
	while(cnt>0)
	{
		if (comparator(item, &(q->data[cur])) == 0) {
			*result = &(q->data[cur]);
			return RETVAL_OK;
		}
		cur = (cur+1)%FCR_SIZE;
		cnt--;
	}

	return RETVAL_OK_AND_CANT_CONTINUE;
}



void fcr_printQueue(FiloCircArr *q)
{

	VPRINT2(KERN_INFO LOGS_TAG "Head is: #%d", q->head);
	fw_logs_print_logent_report_if_verbose(&q->data[q->head]);
	VPRINT2(KERN_INFO LOGS_TAG "Tail is: #%d:", q->tail);
	fw_logs_print_logent_report_if_verbose(&q->data[q->tail]);

	int cur  = q->head;
	int cnt  = q->nvalids;
	while(cnt>0)
	{
		VPRINT2(KERN_INFO LOGS_TAG "Element #%d =", cur);
		fw_logs_print_logent_report_if_verbose(&q->data[cur]);
		cur = (cur+1)%FCR_SIZE;
		cnt--;
	}
	return;
}

