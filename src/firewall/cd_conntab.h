

#ifndef SRC_CD_CONNTAB_H_
#define SRC_CD_CONNTAB_H_


#include "cd_chardevices_env.h"
#include "cd_chardevices_handler.h"




// 						char device : CONNTABS
// ===================================================================


#define CD_CONNTAB_CHARDEV_NAME						"fw_conntab"
#define CD_CONNTAB_SYSFS_DEV_NAME					"fw_conntab"
#define CD_CONNTAB_SYSFS_ATTR_UPDATE_ENTRY_NAME		conntab_update		// non string
#define CD_CONNTAB_SYSFS_ATTR_GET_ENTRY_NAME		conntab_get			// non string


int createConntabCD(struct class* cd_fw_sysfs_class);
void destroyConntabCD(struct class* cd_fw_sysfs_class);


ssize_t storeToUpdateEntry(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t storeToSetKey(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t showToGetEntry(struct device *dev, struct device_attribute *attr, char *buf);




int openCdConntab(struct inode *_inode, struct file *_file);
ssize_t readToGetConntab(struct file *, char __user *, size_t, loff_t *);
int releaseCdfileConntab(struct inode *, struct file *);




// ===================================================================



#endif /* SRC_CD_CONNTAB_H_ */
