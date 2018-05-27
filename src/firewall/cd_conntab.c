
#include "cd_conntab.h"



// 						device configuration
// ===================================================================
// device id's
static int cd_conntab_major_num = 1;

static struct device* cd_conntab_sysfs_device = NULL;

// setup char device file-ops
static struct file_operations cd_conntab_fops = {
		.owner = THIS_MODULE,
		.open = openCdConntab,
		.read = readToGetConntab,
		.write = NULL,	 			 // unimplemented ops should be set to NULL
		// (http://www.tldp.org/LDP/lkmpg/2.4/html/x579.html)
		.release = releaseCdfileConntab, // close
};

// device attributes struct
//	 (by macro: (name, mode, show, store))
//   (must be declared before device_create_file for userspace to recognize it)

static ATTR_STRUCT(CD_CONNTAB_SYSFS_ATTR_UPDATE_ENTRY_NAME, S_IWOTH,
		NULL, storeToUpdateEntry);

static ATTR_STRUCT(CD_CONNTAB_SYSFS_ATTR_GET_ENTRY_NAME, S_IROTH | S_IWOTH,
		showToGetEntry, storeToSetKey);



// ===================================================================





// 						create / destroy
// ===================================================================

int createConntabCD(struct class* cd_fw_sysfs_class){

	VPRINT2(KERN_INFO CD_TAG "creating cd - fw_conntab");

	// create cd
	cd_conntab_major_num = register_chrdev(0, CD_CONNTAB_CHARDEV_NAME, &cd_conntab_fops);
	if (cd_conntab_major_num < 0) goto cleanup_1;

	// create sysfs device
	cd_conntab_sysfs_device = device_create(cd_fw_sysfs_class, NULL,
			MKDEV(cd_conntab_major_num, 0), NULL, CD_CONNTAB_SYSFS_DEV_NAME);
	if (IS_ERR(cd_conntab_sysfs_device)) goto cleanup_3;

	// create sysfs file attributes 1
	if (device_create_file(cd_conntab_sysfs_device,
			AS_DEVATTR(CD_CONNTAB_SYSFS_ATTR_UPDATE_ENTRY_NAME)))
		goto cleanup_4;

	// create sysfs file attributes 2
	if (device_create_file(cd_conntab_sysfs_device,
			AS_DEVATTR(CD_CONNTAB_SYSFS_ATTR_GET_ENTRY_NAME)))
		goto cleanup_5;


	return RETVAL_OK;


	// ERROR HANDLING CLEANUP
	cleanup_5:
	device_remove_file(cd_conntab_sysfs_device,
			AS_DEVATTR(CD_CONNTAB_SYSFS_ATTR_UPDATE_ENTRY_NAME));
	cleanup_4:
	device_destroy(cd_fw_sysfs_class, MKDEV(cd_conntab_major_num, 0));
	cleanup_3:
	//class_destroy(cd_fw_sysfs_class);  - joined class
	//cleanup_2:
	unregister_chrdev(cd_conntab_major_num, CD_CONNTAB_CHARDEV_NAME);
	cleanup_1:
	printk(KERN_INFO CD_TAG "Error creating cd - fw_conntab");
	return RETVAL_ERR;
}


void destroyConntabCD(struct class* cd_fw_sysfs_class){
	device_remove_file(cd_conntab_sysfs_device,
			AS_DEVATTR(CD_CONNTAB_SYSFS_ATTR_GET_ENTRY_NAME));
	device_remove_file(cd_conntab_sysfs_device,
			AS_DEVATTR(CD_CONNTAB_SYSFS_ATTR_UPDATE_ENTRY_NAME));
	device_destroy(cd_fw_sysfs_class, MKDEV(cd_conntab_major_num, 0));
	//class_destroy(cd_fw_sysfs_class);  - joined class
	unregister_chrdev(cd_conntab_major_num, CD_CONNTAB_CHARDEV_NAME);
}

// ===================================================================




// 					sysfs attribute functions
// ===================================================================


ssize_t storeToUpdateEntry(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_conntab/conntab_get - store");

	int rv = fw_filter_stateful_h_update_TCP_connection_from_str_cmd(buf, count);

	// case : ok
	if (rv==RETVAL_OK) return count;
	// case : error
	return EINVAL;
}



ssize_t storeToSetKey(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_conntab/conntab_get - store");
	return count;
}

ssize_t showToGetEntry(struct device *dev,
		struct device_attribute *attr, char *buf){
	VPRINT4(KERN_INFO CD_TAG "sysfs - fw_conntab/conntab_get - show");
	return scnprintf(buf, PAGE_SIZE, "%s\n", "not supported");
}


// ===================================================================





// 							fileop functions
// ===================================================================

static Session conntabs_ses = {SES_CLOSED, 0, 0, NULL, NULL};
static char conntabs_buf[CONS_TOTALSTRING_MAXLEN+1] = {0}; // todo make dyn.alloc

int openCdConntab(struct inode *_inode, struct file *_file){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_conntab - fop open");
	conntabs_ses.stat = SES_NEW; 	// set session status
	return 0;
}

ssize_t readToGetConntab(struct file *filp, char *buf, size_t length, loff_t *offp){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_conntab - fop read");

	// handle a new session
	if (conntabs_ses.stat == SES_NEW){
		conntabs_ses.buf = conntabs_buf;
		conntabs_ses.buf_idx = conntabs_ses.buf;									// set buf_idx to start of data
		conntabs_ses.nbytes_total = 0;
		fw_cons_get_all_as_string(conntabs_ses.buf, &conntabs_ses.nbytes_left);		// get data to send
		conntabs_ses.stat = SES_ONGOING_READ;
	}

	// handle an ongoing session
	return sessionHandlerSendToUser(buf, length, &conntabs_ses);
}

int releaseCdfileConntab(struct inode *_inode, struct file *file){
	VPRINT4(KERN_INFO CD_TAG "cd - fw_conntab - fop close");
	return 0;
}
// ===================================================================

