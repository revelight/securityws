

#ifndef SRC_CD_LOGS_H_
#define SRC_CD_LOGS_H_



#include "cd_chardevices_env.h"
#include "cd_chardevices_handler.h"



// 						char device : FW_LOGS
// ===================================================================


#define CD_LOG_CHARDEV_NAME					"fw_log"
#define CD_LOG_SYSFS_DEV_NAME				"fw_log"
#define CD_LOG_SYSFS_ATTR_LOGSIZE_NAME		log_size	// non string
#define CD_LOG_SYSFS_ATTR_LOGCLR_NAME		log_clear	// non string


int createLogsCD(struct class* cd_fw_sysfs_class);
void destroyLogCD(struct class* cd_fw_sysfs_class);

ssize_t showToGetNumOfLogTableLines(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t storeToClearLogTable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

int openCdLog(struct inode *_inode, struct file *_file);
ssize_t readToGetLog(struct file *, char __user *, size_t, loff_t *);
int releaseCdfileLog(struct inode *, struct file *);

// ===================================================================




#endif /* SRC_CD_LOGS_H_ */
