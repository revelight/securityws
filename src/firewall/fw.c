
#include "fw.h"


// === MODULE INIT / EXIT



// Initialize Module. (Note: Local func mem will be released after first use due to macro)
static int __init fw_module_init(void) {
	printk(KERN_INFO "\n\n\n========= FW: Module init.. ===========\n\n\n");

	// init char devices
	if (cd_init_char_devices() == RETVAL_ERR) goto err_cleanup;

	// init firewall
	if (fw_traffic_man_init() == RETVAL_ERR) goto err_cleanup;

	// init netfilter hooking
	if (nf_init_hooks() == RETVAL_ERR) goto err_cleanup;



	// All good! / Error: non-0 return init_module failed
	return 0;


	err_cleanup:
		return RETVAL_ERR;
}



static void __exit fw_module_exit(void) {	
	printk(KERN_INFO "\n\n\n========= FW: Module exit.. ===========\n\n\n");

	// destroy char devices
	cd_destroy_char_devices();

	// destroy net filter hooks
	nf_destroy_hooks();

	// destroy firewall
	fw_traffic_man_destroy();


}



module_init(fw_module_init); // Kernel Macro: for init_module(), allows freeing kernel memory
module_exit(fw_module_exit); // Kernel Macro: for cleanup_module()


