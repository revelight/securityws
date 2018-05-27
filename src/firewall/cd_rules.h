

#ifndef SRC_CD_RULES_H_
#define SRC_CD_RULES_H_


#include "cd_chardevices_env.h"
#include "cd_chardevices_handler.h"



// 						char device : FW_RULES
// ===================================================================


#define CD_RULES_CHARDEV_NAME				"fw_rules"
#define CD_RULES_SYSFS_DEV_NAME 			"fw_rules"
#define CD_RULES_SYSFS_ATTR_ACTIVE_NAME		active		// non string
#define CD_RULES_SYSFS_ATTR_RULSIZE_NAME	rules_size	// non string


int createRulesCD(struct class* cd_fw_sysfs_class);
void destroyRulesCD(struct class* cd_fw_sysfs_class);

ssize_t showToGetFwActiveStatus(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t storeToSetActiveOrNot(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t showToGetNumOfRules(struct device *dev, struct device_attribute *attr, char *buf);

int openCdRules(struct inode *_inode, struct file *_file);
ssize_t readToGetRules(struct file *, char __user *, size_t, loff_t *);
ssize_t writeToSetRules(struct file *, const char __user *, size_t, loff_t *);
int releaseCdfileRules(struct inode *, struct file *);

int cd_rules_set_from_str(char* str, int len);

// ===================================================================

#endif /* SRC_CD_RULES_H_ */
