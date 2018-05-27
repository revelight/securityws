

#ifndef SRC_ENV_KERNEL_H_
#define SRC_ENV_KERNEL_H_



// === Kernel Environment includes and tools
// include it =before= any others in headers

#include <linux/module.h>			// Needed by all modules
#include <linux/kernel.h>			// Needed for KERN_INFO and for the macros

//#include <linux/slab.h>			// Kernel Mem Allocations



#define IDE_MODE 0		// Disable in final src \ build




// === IDE DEV ONLY - includes and flags for dev markup
#if IDE_MODE == 1

// ... IDE: kernel environment include flags, for system headers below
#define __KERNEL__
#define CONFIG_NETFILTER

// ... IDE: direct system includes
#include "linux/init.h"
#include "unistd.h"
#include "asm-generic/page.h"
#include "linux/printk.h"
#include "linux/fs.h"
#include "linux/stat.h"
#include "asm-generic/uaccess.h"
#include "linux/gfp.h"
#include "linux/netfilter_ipv4.h"
#include "linux/netfilter.h"
#include "linux/slab.h"
#include "unistd.h"
#include "linux/device.h"
#include "linux/fs.h"
#include "linux/ip.h"
#include "linux/tcp.h"
#include "linux/udp.h"
#include "linux/skbuff.h"
#include "linux/gfp.h"
#include "linux/time.h"
#include "linux/errno.h"
#include "linux/types.h"

#undef __KERNEL__


#define __KERNEL__

#endif // === IDE Mode





#endif /* SRC_ENV_KERNEL_H_ */
