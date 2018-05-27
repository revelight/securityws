
#include "cd_chardevices_handler.h"





// 						create / destroy
// ===================================================================

static struct class* cd_fw_sysfs_class = NULL; // joint class for all char devices)

int cd_init_char_devices(void) {
	// create class first
	if (RETVAL_ERR == createFwClass()) return RETVAL_ERR;

	if (RETVAL_ERR == createLogsCD(cd_fw_sysfs_class)) return RETVAL_ERR;
	if (RETVAL_ERR == createRulesCD(cd_fw_sysfs_class)) return RETVAL_ERR;
	if (RETVAL_ERR == createConntabCD(cd_fw_sysfs_class)) return RETVAL_ERR;

	return RETVAL_OK;
}


void cd_destroy_char_devices(void) {
	destroyLogCD(cd_fw_sysfs_class);
	destroyRulesCD(cd_fw_sysfs_class);
	destroyConntabCD(cd_fw_sysfs_class);

	// destroy class last
	destroyFwClass();
}
// ===================================================================




// 						SysFs Class : fw
// ===================================================================
int createFwClass(void){
	// create sysfs class
	cd_fw_sysfs_class = class_create(THIS_MODULE, CD_ALL_SYSFS_CLASS_NAME);
	if (IS_ERR(cd_fw_sysfs_class))
		return RETVAL_ERR;
	return RETVAL_OK;
}
void destroyFwClass(void){
	class_destroy(cd_fw_sysfs_class);
}
// ===================================================================






// 						FileOps - Helpers
// ===================================================================

// handle a read call in a an open session -- send data portion to user
int sessionHandlerSendToUser(char *buf, size_t length, Session* ses){

	if (ses->stat == SES_ONGOING_READ){
		// try to send all session's bytes left,
		// but not over this call's requested length  = min(left to send,request)
		ssize_t nbytes_call = (ses->nbytes_left < length) ? ses->nbytes_left : length;

		if (nbytes_call == 0){
			return 0; // no bytes should be sent this call (user asked 0 or no more left)
		}

		// send data from kernel to user
		if (copy_to_user(buf, ses->buf_idx, nbytes_call)) { // returns #bytes not copied, any non 0 is an error
			return -EFAULT; // the typical error case
		}
		else // call's data portion sent ok, update session progress
		{
			ses->nbytes_left -= nbytes_call;
			ses->buf_idx += nbytes_call;

			if (ses->nbytes_left == 0){ // session complete -- all session bytes sent
				// continue returning 0 to user calls
				// or could also set session to end and thus return -EFAULT on future calls: ses->SES_WAITING_CLOSE;
			}
			return nbytes_call;
		}
		return nbytes_call;
	}
	return -EFAULT; // should not get here
}

// handle a write call in a an open session -- receive data portion from user
int sessionHandlerRecieveFromUser(const char *buf, size_t length, Session* ses){

	// a call in a session - receive data portion from user
	if (ses->stat == SES_ONGOING_WRITE){

		// try to receive all session's available bytes
		// but not over call's requested length  = min(avail,request)
		ssize_t nbytes_call = (ses->nbytes_left < length) ? ses->nbytes_left : length;

		if (nbytes_call == 0){
			return 0; // no bytes should be received this call (user asked 0 or no more available)
		}

		// receive data from user to kernel
		if (copy_from_user(ses->buf_idx, buf, nbytes_call)) { // returns #bytes not copied, any non 0 is an error
			return -EFAULT; // the typical error case
		}
		else { // call's data portion sent ok, update session progress
			ses->nbytes_total += nbytes_call;
			ses->buf_idx += nbytes_call;
			if (ses->nbytes_left == 0) { // session complete -- no more available capacity
				// continue returning 0 to user calls
				// or could also set session to end and thus return -EFAULT on future calls: ses->SES_WAITING_CLOSE;
				return nbytes_call;
			}
		}
		return nbytes_call;
	}
	return -EFAULT; // should not get here
}

// ===================================================================



