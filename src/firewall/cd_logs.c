
#include "cd_logs.h"



// 						device configuration
// ===================================================================
// device id's
static int cd_log_major_num = 1;

static struct device* cd_log_sysfs_device = NULL;

// setup char device file-ops
static struct file_operations cd_log_fops = {
		.owner = THIS_MODULE,
		.open = openCdLog,
		.read = readToGetLog,
		.write = NULL,	 			 // unimplemented ops should be set to NULL (http://www.tldp.org/LDP/lkmpg/2.4/html/x579.html)
		.release = releaseCdfileLog, // close
};

// device attributes struct
//	 (by macro: (name, mode, show, store))
//   (must be declared before device_create_file for userspace to recognize it)

static ATTR_STRUCT(CD_LOG_SYSFS_ATTR_LOGSIZE_NAME, S_IROTH,
		showToGetNumOfLogTableLines, NULL);

static ATTR_STRUCT(CD_LOG_SYSFS_ATTR_LOGCLR_NAME, S_IWOTH,
		NULL, storeToClearLogTable);
// ===================================================================





// 						create / destroy
// ===================================================================

int createLogsCD(struct class* cd_fw_sysfs_class){

	printk(KERN_INFO CD_TAG "creating cd - fw_log");

	// create cd
	cd_log_major_num = register_chrdev(0, CD_LOG_CHARDEV_NAME, &cd_log_fops);
	if (cd_log_major_num < 0) goto cleanup_1;

	// create sysfs device
	cd_log_sysfs_device = device_create(cd_fw_sysfs_class, NULL,
			MKDEV(cd_log_major_num, 0), NULL, CD_LOG_SYSFS_DEV_NAME);
	if (IS_ERR(cd_log_sysfs_device)) goto cleanup_3;

	// create sysfs file attributes 1
	if (device_create_file(cd_log_sysfs_device,
			AS_DEVATTR(CD_LOG_SYSFS_ATTR_LOGSIZE_NAME)))
		goto cleanup_4;

	// create sysfs file attributes 2
	if (device_create_file(cd_log_sysfs_device,
			AS_DEVATTR(CD_LOG_SYSFS_ATTR_LOGCLR_NAME)))
		goto cleanup_5;


	return RETVAL_OK;

	// ERROR HANDLING CLEANUP
	cleanup_5:
	device_remove_file(cd_log_sysfs_device,
			AS_DEVATTR(CD_LOG_SYSFS_ATTR_LOGSIZE_NAME));
	cleanup_4:
	device_destroy(cd_fw_sysfs_class, MKDEV(cd_log_major_num, 0));
	cleanup_3:
	//class_destroy(cd_fw_sysfs_class);  - joined class
	//cleanup_2:
	unregister_chrdev(cd_log_major_num, CD_LOG_CHARDEV_NAME);
	cleanup_1:
	printk(KERN_INFO CD_TAG "Error creating cd - fw_log");
	return RETVAL_ERR;
}


void destroyLogCD(struct class* cd_fw_sysfs_class){
	device_remove_file(cd_log_sysfs_device,
			AS_DEVATTR(CD_LOG_SYSFS_ATTR_LOGCLR_NAME));
	device_remove_file(cd_log_sysfs_device,
			AS_DEVATTR(CD_LOG_SYSFS_ATTR_LOGSIZE_NAME));
	device_destroy(cd_fw_sysfs_class, MKDEV(cd_log_major_num, 0));
	//class_destroy(cd_fw_sysfs_class);  - joined class
	unregister_chrdev(cd_log_major_num, CD_LOG_CHARDEV_NAME);
}

// ===================================================================






// 					sysfs attribute functions
// ===================================================================
ssize_t showToGetNumOfLogTableLines(struct device *dev,
		struct device_attribute *attr, char *buf){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_log/log_size - read");
	return scnprintf(buf, PAGE_SIZE, "%u\n", fw_logs_getNumOfEntries());
}

ssize_t storeToClearLogTable(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_log/log_clear - clear");
	fw_logs_clearAll();
	return count;
}
// ===================================================================






// 							fileop functions
// ===================================================================

static Session logs_ses = {SES_CLOSED, 0, 0, NULL, NULL};
static char logs_buf[LOGS_TOTALSTRING_MAXLEN+1] = {0}; // todo make dyn.alloc

int openCdLog(struct inode *_inode, struct file *_file){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_log - fop open");
	logs_ses.stat = SES_NEW; 	// set session status
	return 0;
}

ssize_t readToGetLog(struct file *filp, char *buf, size_t length, loff_t *offp){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_log - fop read");

	// handle a new session
	if (logs_ses.stat == SES_NEW){
		logs_ses.buf = logs_buf;
		logs_ses.buf_idx = logs_ses.buf;									// set buf_idx to start of data
		logs_ses.nbytes_total = 0;
		fw_logs_get_all_as_string(logs_ses.buf, &logs_ses.nbytes_left);		// get data to send
		logs_ses.stat = SES_ONGOING_READ;
	}

	// handle an ongoing session
	return sessionHandlerSendToUser(buf, length, &logs_ses);
}

int releaseCdfileLog(struct inode *_inode, struct file *file){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_log - fop close");
	return 0;
}
// ===================================================================

