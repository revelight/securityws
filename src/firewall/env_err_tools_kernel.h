

#ifndef SRC_ERRORHANDLER_H_
#define SRC_ERRORHANDLER_H_

#include "env_kernel.h"

// Macro Tools
#define STRINGIZE(i) #i
#define TOSTR(i) STRINGIZE(i)


// Verbose level based msgs
#define VERBOSE 2


#if VERBOSE == 4
	#define VPRINT4(...) printk(__VA_ARGS__)
	#define VPRINT3(...) printk(__VA_ARGS__)
	#define VPRINT2(...) printk(__VA_ARGS__)
	#define VPRINT1(...) printk(__VA_ARGS__)

#elif VERBOSE == 3
	#define VPRINT4(...)
	#define VPRINT3(...) printk(__VA_ARGS__)
	#define VPRINT2(...) printk(__VA_ARGS__)
	#define VPRINT1(...) printk(__VA_ARGS__)

#elif VERBOSE == 2
	#define VPRINT4(...)
	#define VPRINT3(...)
	#define VPRINT2(...) printk(__VA_ARGS__)
	#define VPRINT1(...) printk(__VA_ARGS__)

#elif VERBOSE == 1
	#define VPRINT4(...)
	#define VPRINT3(...)
	#define VPRINT2(...)
	#define VPRINT1(...) printk(__VA_ARGS__)
#endif


// Test Tools
#define TEST_MODE 1
#if TEST_MODE == 1
// #include "MG/MemGateway.h"
//#define MALLOC(size) myMalloc(size, __func__, __LINE__)
//#define CALLOC(elems, size) myCalloc(elems, size, __func__, __LINE__)
//#define FREE(mem) myFree(mem, __func__, __LINE__)
#define TPRINTK(s) printk(s)
#define TFUNCSTART 	printk(KERN_ALERT "<func start: " TOSTR(__func__) ">\n")
#define TFUNCEND 	printk(KERN_ALERT "<func   end: " TOSTR(__func__) ">\n")
#else
#define MALLOC(size) kmalloc(size, GFP_KERNEL)
#define CALLOC(elems, size) kcalloc(elems, size, GFP_KERNEL)
#define FREE(mem) kfree(mem)
#define TPRINTK()
#define TFUNCSTART
#define TFUNCEND
#endif


// Return Values
#define RETVAL_ERR -1
#define RETVAL_OK 0
#define RETVAL_OK_AND_CANT_CONTINUE -2
#define RETVAL_OK_AND_FAIL -3


// Error Reporting
#define ERR_TAG  "======== ERROR : "
#define SERR_TAG "==== SYS ERROR : "
#define PERR(...) perr(__VA_ARGS__,__FILE__, __func__, __LINE__)

typedef enum t_err_type{
	ERR,
	ERR_ALLOC,
	ERR_SYS
} ERRT;


// Functions
void perr(ERRT errt, const char* msg,
		const char* file, const char* func, const int line);






#endif /* SRC_ERRORHANDLER_H_ */
