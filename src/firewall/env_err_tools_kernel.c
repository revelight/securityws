

#include "env_err_tools_kernel.h"


void perr(ERRT errt, const char* msg,
		const char* file, const char* func, const int line){
		printk(KERN_ALERT "%s%s [%s : %s : %d] : ", SERR_TAG, msg, file, func, line);
}

