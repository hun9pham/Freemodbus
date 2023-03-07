#ifndef __APP_H
#define __APP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include "mb.h"
#include "mbport.h"

//----------------------------------------------------------------------------------//
//-- General defines
//----------------------------------------------------------------------------------//
#define RET_NG                  ( -1 )
#define RET_OK                  ( 1 )
#define RET_PORT_DISCONNECT     ( 0 )

//----------------------------------------------------------------------------------//
//-- File path value register defines
//----------------------------------------------------------------------------------//
#define BMS_FILE_PATH					        ( "/home/hung/WORKSPACE/linux-modbus-slave-app/FREEMODBUS/demo/modifyLINUX/BMS.txt" )
#define mbSLAVE_FILE_CONFIG_PATH                ( "/home/hung/WORKSPACE/linux-modbus-slave-app/FREEMODBUS/demo/modifyLINUX/mbslave_info.cfg" )
#define mbSLAVE_LOG_MSG_REQ_PATH                ( "/home/hung/WORKSPACE/linux-modbus-slave-app/FREEMODBUS/demo/modifyLINUX/log_req_msg.txt" )

//----------------------------------------------------------------------------------//
//-- Modbus slave default setting defines
//----------------------------------------------------------------------------------//
#define mbLSAVE_ID_DEFAULT  			        ( 0x01 )
#define mbLSAVE_BAUDRATE_DEFAULT	            ( 9600 )
#define mbSLAVE_SERIAL_DEFAULT                  ( "/dev/ttyUSB0" )
#define mbLSAVE_PARITY_DEFAULT  	            ( MB_PAR_NONE )

//-- Typedef -----------------------------------------------------------------------//
typedef struct {
    UCHAR mbId;
    UCHAR mbPort[16];
    ULONG mbBaud_Rate;
    eMBParity mbParity;
} mbslave_info_t;;

typedef struct {
    mbslave_info_t *mbsl;
    uint8_t  reg_mode;
    USHORT reg_addr;
    int reg_idx;
    USHORT reg_val;
} log_msg_info_t;

//-- Extern variables --------------------------------------------------------------//
extern mbslave_info_t mbSlave;
extern log_msg_info_t log_msg;

//-- Function prototypes ----------------------------------------------------------//
extern int8_t mbslave_flexible_config(void);
extern int8_t mbslave_register_update(void);
extern int8_t serial_port_tracking(char *port_name);
extern void   save_log_req_message(log_msg_info_t *);


#ifdef __cplusplus
}
#endif

#endif