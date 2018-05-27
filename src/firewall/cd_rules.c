


#include "cd_rules.h"


// 						device configuration
// ===================================================================

// device id's
static int cd_rules_major_num = 0;
static struct device* cd_rules_sysfs_device = NULL;

// setup char device file-ops
static struct file_operations cd_rules_fops = {
		.owner = THIS_MODULE,
		.open = openCdRules,
		.read = readToGetRules,
		.write = writeToSetRules,
		.release = releaseCdfileRules, // close
};

// device attributes struct,
static ATTR_STRUCT(CD_RULES_SYSFS_ATTR_ACTIVE_NAME, S_IROTH | S_IWOTH,
		showToGetFwActiveStatus, storeToSetActiveOrNot);
static ATTR_STRUCT(CD_RULES_SYSFS_ATTR_RULSIZE_NAME, S_IROTH,
		showToGetNumOfRules, NULL);
// ===================================================================





// 						create / destroy
// ===================================================================

int createRulesCD(struct class* cd_fw_sysfs_class){

	printk(KERN_INFO CD_TAG "creating cd - fw_rules");

	// create cd
	cd_rules_major_num = register_chrdev(0, CD_RULES_CHARDEV_NAME, &cd_rules_fops);
	if (cd_rules_major_num < 0) goto cleanup_1;

	// create sysfs device
	cd_rules_sysfs_device = device_create(cd_fw_sysfs_class, NULL,
			MKDEV(cd_rules_major_num, 0), NULL, CD_RULES_SYSFS_DEV_NAME);
	if (IS_ERR(cd_rules_sysfs_device)) goto cleanup_3;

	// create sysfs file attributes 1
	if (device_create_file(cd_rules_sysfs_device,
			AS_DEVATTR(CD_RULES_SYSFS_ATTR_ACTIVE_NAME)))
		goto cleanup_4;

	// create sysfs file attributes 2
	if (device_create_file(cd_rules_sysfs_device,
			AS_DEVATTR(CD_RULES_SYSFS_ATTR_RULSIZE_NAME)))
		goto cleanup_5;


	return RETVAL_OK;


	// ERROR HANDLING CLEANUP
	cleanup_5:
	device_remove_file(cd_rules_sysfs_device,
			AS_DEVATTR(CD_RULES_SYSFS_ATTR_ACTIVE_NAME));
	cleanup_4:
	device_destroy(cd_fw_sysfs_class, MKDEV(cd_rules_major_num, 0));
	cleanup_3:
	//class_destroy(cd_fw_sysfs_class); - joined class
	//cleanup_2:
	unregister_chrdev(cd_rules_major_num, CD_RULES_CHARDEV_NAME);
	cleanup_1:
	printk(KERN_INFO CD_TAG "Error creating cd - fw_rules");
	return RETVAL_ERR;
}

void destroyRulesCD(struct class* cd_fw_sysfs_class){
	device_remove_file(cd_rules_sysfs_device,
			AS_DEVATTR(CD_RULES_SYSFS_ATTR_RULSIZE_NAME));
	device_remove_file(cd_rules_sysfs_device,
			AS_DEVATTR(CD_RULES_SYSFS_ATTR_ACTIVE_NAME));
	device_destroy(cd_fw_sysfs_class, MKDEV(cd_rules_major_num, 0));
	//class_destroy(cd_rules_sysfs_class);  - joined class
	unregister_chrdev(cd_rules_major_num, CD_RULES_CHARDEV_NAME);
}
// ===================================================================






// 					sysfs attribute functions
// ===================================================================

ssize_t storeToSetActiveOrNot(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count){
	//printk(KERN_INFO CD_TAG "sysfs - fw_rules/active - set");
	int mode;
	if (count == 1 &&
			sscanf(buf, USR_SYSFS_RULES_ACTIVE_FORMAT, &mode) == 1){ // single uint
		if (-1<mode && mode<FW_ENUM_LIMIT){ // in enum range
			fw_trafficman_setActiveStatus((FW_STATE)mode);
			VPRINT4(KERN_INFO CD_TAG "sysfs - fw_rules/active - set to: %d", mode);
			return 1;
		}
	}

	// bad arg!
	return USR_SYSFS_STORE_RETVAL_ERR;
}

ssize_t showToGetFwActiveStatus(struct device *dev, struct device_attribute *attr,
		char *buf){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_rules/active - read");
	return scnprintf(buf, PAGE_SIZE, USR_SYSFS_RULES_ACTIVE_FORMAT,
			fw_trafficman_getActiveStatus());
}


ssize_t showToGetNumOfRules(struct device *dev, struct device_attribute *attr, char *buf){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_rules/rules_size - read");
	return scnprintf(buf, PAGE_SIZE, USR_SYSFS_RULES_SIZE_FORMAT,
			fw_rules_getNumOfEntries());
}
// ===================================================================







// 							fileop functions
// ===================================================================

static Session rules_ses = {SES_CLOSED, 0, 0, NULL, NULL};
static char rules_buf[RULES_TOTALSTRING_MAXLEN+1] = {0}; // todo make dyn.alloc

// fileop "open" - user opens file
int openCdRules(struct inode *_inode, struct file *_file){
	rules_ses.stat = SES_NEW; 	// set session status
	VPRINT4(KERN_INFO CD_TAG "cd - fw_rules - fop open");
	return 0;
}

// fileop 'read' - user asks for <length> chars at a time - send to user
ssize_t readToGetRules(struct file *filp, char *buf, size_t length, loff_t *offp){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_rules - fop read");

	// handle a new session
	if (rules_ses.stat == SES_NEW){
		rules_ses.buf = rules_buf;
		rules_ses.buf_idx = rules_ses.buf;								// set buf_idx to start of data
		rules_ses.nbytes_total = 0;
		fw_rules_get_as_string(rules_ses.buf, &rules_ses.nbytes_left);	// get data to send to buf and nbytes_left
		rules_ses.stat = SES_ONGOING_READ;
	}

	// handle an ongoing session
	return sessionHandlerSendToUser(buf, length, &rules_ses);
}

// fileop 'write' - user asks to write <length> chars at a time - receive from user
ssize_t writeToSetRules(struct file *filp, const char *buf, size_t length, loff_t *offp){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_rules - fop write");

	// handle a new session
	if (rules_ses.stat == SES_NEW) {
		rules_ses.buf = rules_buf;								// set receiving buffer
		rules_ses.buf_idx = rules_ses.buf;						// set buf_idx to start of receiving buffer
		rules_ses.nbytes_total = 0;
		rules_ses.nbytes_left = RULES_TOTALSTRING_MAXLEN;		// set session receive cap at a certain max
		rules_ses.stat = SES_ONGOING_WRITE;
	}

	// handle an ongoing session
	return sessionHandlerRecieveFromUser(buf, length, &rules_ses);
}

// fileop 'close' - user closes file
int releaseCdfileRules(struct inode *_inode, struct file *file){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_rules - fop close");

	switch (rules_ses.stat) {
	case SES_ONGOING_READ:
		break;
	case SES_ONGOING_WRITE:
		cd_rules_set_from_str(rules_ses.buf, rules_ses.nbytes_total);
		break;
	default:
		break;
	}
	rules_ses.stat = SES_CLOSED;
	return 0;
}
// ===================================================================





// 					command support functions
// ===================================================================

int cd_rules_set_from_str(char* str, int len){

	VPRINT4(KERN_INFO CD_TAG RULES_CMD_TAG "set rules excerpt: %.100s", str);

	// first clear connection table (if active)
	fw_cons_clear_all();
	// then clear rules
	fw_rules_reset();


	// --- support user commands via chardevice ---

	// reset only
	if (strncmp(str,USER_CD_RULES_RESET_CMD, USER_CD_RULES_RESET_CMD_LEN)==0){
		VPRINT4(KERN_INFO  RULES_CMD_TAG  "clearing rules");
		return RETVAL_OK;
	}

	// default : add rules from list
	fw_rules_add_from_str(str, len);


	return RETVAL_OK;
}

// ===================================================================




