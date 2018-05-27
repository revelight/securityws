

#ifndef SRC_CD_CHARDEVICES_ENV_H_
#define SRC_CD_CHARDEVICES_ENV_H_



// == CHAR (AND SYSFS) DEVICE

// Module
#include "env_program.h"
#include "fw_traffic_man.h"
#include "fw_userclient_protocol.h"


#include <linux/fs.h>		// For Char device
#include <linux/device.h>	// For Char device
#include <asm/uaccess.h>	// For data transfer, kernel<->user


#define CD_TAG "_cd          - "


// === Char-Device and Sysfs

// Sysfs path: 		/sys/class/mySysClass/mySysDevice/myAttr
// CharDevice path:	/dev/mySysDevice
// note: register_chrdev name used only as internal id
// note: for myAttr use non-string values

#define CD_ALL_SYSFS_CLASS_NAME "fw"



// .. attribute casting helper macros
#define ATTR_STRUCT(name,mode,show,store) DEVICE_ATTR(name,mode,show,store)
#define DEVATTR_PASTER(x) (const struct device_attribute *)&dev_attr_##x.attr
#define AS_DEVATTR(x) DEVATTR_PASTER(x)


typedef enum t_session_status{
	SES_CLOSED,
	SES_NEW,
	SES_ONGOING_READ,
	SES_ONGOING_WRITE,
	SES_AWAITING_TO_CLOSE,
} SES_STATUS;


typedef struct t_session{
	SES_STATUS stat;		// file session status
	int nbytes_total;		// total bytes transfered, in a session (on write we don't know this value)
	int nbytes_left;		// bytes left to transfer in the session - left to send or available to receive
	char* buf;				// session kernel-side buffer -- send to user / write from user
	char* buf_idx;			// moving index to follow intermediate calls in the session
} Session;


// device minor numbers
typedef enum {
	MINOR_RULES    = 244,
	MINOR_LOG      = 245,
	MINOR_CONNTAB  = 255,
} minor_t;






#endif /* SRC_CD_CHARDEVICES_ENV_H_ */
