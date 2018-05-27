

#ifndef SRC_CD_CHARDEVICES_HANDLER_H_
#define SRC_CD_CHARDEVICES_HANDLER_H_


#include "cd_chardevices_env.h"

#include "cd_rules.h"
#include "cd_logs.h"
#include "cd_conntab.h"



// == FUNCTIONS


// Char Devices
int cd_init_char_devices(void);
void cd_destroy_char_devices(void);

int createFwClass(void);
void destroyFwClass(void);


// .. FileOps - Helpers
int sessionHandlerSendToUser(char *buf, size_t length, Session* ses);
int sessionHandlerRecieveFromUser(const char *buf, size_t length, Session* ses);



#endif /* SRC_CD_CHARDEVICES_HANDLER_H_ */
