/* ----------------------- Standard includes --------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

/* ----------------------- Modbus includes ----------------------------------*/
#include "mb.h"
#include "mbport.h"

/* ----------------------- User includes --------------------------------*/
#include "app.h"


//-- Extern variables --------------------------------------------------------------//
mbslave_info_t mbSlave;
log_msg_info_t log_msg;

//----------------------------------------------------------------------------------//
//-- Modbus slave register defines
//----------------------------------------------------------------------------------//
#define mbSLAVE_REG_VALUE_DEFAULT               ( 0xFFF )

#define mbSLAVE_REG_START_ADDR					( 40000 )
#define mbSLAVE_REG_NREGS                       ( 60 )
#define mbSLAVE_REG_MOD_INDEX					( 48 )	/* Mod=1 Manuel Mod, Mod=2 Stop Mod, Mod=3 Auto Mod */
#define mbSLAVE_REG_SISTEM_BAR_INDX				( 44 )  /* Bar=Value*10 Ornk(3,2 Bar -> 32(Value) */
#define mbSLAVE_REG_SET_BAR_VALUE_INDX			( 50 )  /* Bar=Value*10 Ornk(3,2 Bar -> 32(Value) */
#define mbSLAVE_REG_TANK_DOLULUK_DEGERI_INDX	( 49 )  /* %0-100 Range */
#define mbSLAVE_REG_ERROR_INDX					( 40 )  /* If there is an error, the code is on the line. If there is no error, the value 0 is displayed. */
#define mbSLAVE_REG_STATUS_INDX					( 35 )  /* Returns 1 if the System is Working, Returns 0 if there is an Error in the System */

#define sub_mbSLAVE_REG_START_ADDR              ( 0 )
#define sub_mbSLAVE_REG_NREGS                   ( 60 )

/* ----------------------- End USER-Defines ------------------------------------------*/


/* ----------------------- Defines ------------------------------------------*/
#define PROG            "freemodbus"

#define REG_INPUT_START         ( 1000 )
#define REG_INPUT_NREGS         ( 10 )
#define REG_HOLDING_START       ( mbSLAVE_REG_START_ADDR )
#define REG_HOLDING_NREGS       ( mbSLAVE_REG_NREGS )

#define subREG_HOLDING_START       ( sub_mbSLAVE_REG_START_ADDR )
#define subREG_HOLDING_NREGS       ( sub_mbSLAVE_REG_NREGS )


/* ----------------------- Static variables ---------------------------------*/
#if 0
static USHORT   usRegInputStart = REG_INPUT_START;
static USHORT   usRegInputBuf[REG_INPUT_NREGS];
static USHORT   usRegHoldingStart = REG_HOLDING_START;
static USHORT   usRegHoldingBuf[REG_HOLDING_NREGS];
#else
/*******************************
 * @brief USER DEFINE REGISTER *
 *******************************/
static USHORT   usRegInputStart = REG_INPUT_START;
static USHORT   usRegInputBuf[REG_INPUT_NREGS];
static USHORT   usRegHoldingStart = REG_HOLDING_START;
static USHORT   usRegHoldingBuf[REG_HOLDING_NREGS];

static USHORT   tmp_usRegHoldingStart = subREG_HOLDING_START;
static USHORT   tmp_usRegHoldingBuf[subREG_HOLDING_NREGS];
#endif

static enum ThreadState
{
    STOPPED,
    RUNNING,
    SHUTDOWN
} ePollThreadState;

static pthread_mutex_t xLock = PTHREAD_MUTEX_INITIALIZER;
static BOOL     bDoExit;

/* ----------------------- Static functions ---------------------------------*/
static BOOL     bCreatePollingThread( void );
static enum ThreadState eGetPollingThreadState( void );
static void     vSetPollingThreadState( enum ThreadState eNewState );
static void    *pvPollingThread( void *pvParameter );

/* ----------------------- Start implementation -----------------------------*/

int main( int argc, char *argv[] )
{   
    int             iExitCode;
    CHAR            cCh;
    /**********************************
     * @brief Setup modbus slave info *
     ***********************************/
    if (mbslave_flexible_config() < 0) {
        printf("[error] Not-FOUND \"mbslave_info.cfg\"\n");

        mbSlave.mbId = mbLSAVE_ID_DEFAULT;
        mbSlave.mbBaud_Rate = mbLSAVE_BAUDRATE_DEFAULT;
        memcpy((uint8_t *)mbSlave.mbPort, (uint8_t *)mbSLAVE_SERIAL_DEFAULT, strlen(mbSLAVE_SERIAL_DEFAULT));
        mbSlave.mbParity = MB_PAR_NONE;

        /* from portserial.c */
        extern UCHAR g_PortOpen[16];
        memcpy((uint8_t *)g_PortOpen, (uint8_t *)mbSLAVE_SERIAL_DEFAULT, strlen(mbSLAVE_SERIAL_DEFAULT));
    }

    //-- Set up log message -----------------//
    memset(&log_msg, 0, sizeof(log_msg_info_t));
    log_msg.mbsl = &mbSlave;


    if( eMBInit( MB_RTU, mbSlave.mbId, 0, mbSlave.mbBaud_Rate, mbSlave.mbParity ) != MB_ENOERR )
    {
        fprintf( stderr, "%s: can't initialize modbus stack!\n", PROG );
        iExitCode = EXIT_FAILURE;
    }
    else
    {
        /**
         * @brief Set default value for all Reg holding
         ****/
        int iDx;
        for (iDx = 0; iDx < 60; ++iDx) {
            usRegHoldingBuf[iDx] = ( USHORT )mbSLAVE_REG_VALUE_DEFAULT;
            tmp_usRegHoldingBuf[iDx] = ( USHORT )mbSLAVE_REG_VALUE_DEFAULT;
        }


        /****************************
         * @brief MODBUS SLAVE ECHO *
         ****************************/
        printf("Modbus slave information:\n");
        printf("\t> id..........:%d\n", mbSlave.mbId);
        printf("\t> port........:%s\n", mbSlave.mbPort);
        printf("\t> baud-rate...:%ld\n", mbSlave.mbBaud_Rate);
        printf("\t> parity......:");
        if (mbSlave.mbParity == MB_PAR_ODD) {
            printf("MB_PAR_ODD\n");
        }
        else if (mbSlave.mbParity == MB_PAR_EVEN) {
            printf("MB_PAR_EVEN\n");
        }
        else {
            printf("MB_PAR_NONE\n");
        }

        vSetPollingThreadState( STOPPED );

        /**
         * @brief Start polling modbus slave when initialiize
         *****/
        if( bCreatePollingThread(  ) == TRUE ) {
            printf("Modbus slave app starting...\n");
        }

        /* CLI interface. */
        printf( "Type 'q' for quit or 'h' for help!\n" );
        bDoExit = FALSE;

        do
        {
            printf( "> " );
            cCh = getchar(  );

            switch ( cCh )
            {
            case 'q':
                bDoExit = TRUE;
                break;
            case 'd':
                vSetPollingThreadState( SHUTDOWN );
                break;
            case 'e':
                if( bCreatePollingThread(  ) != TRUE )
                {
                    printf( "Can't start protocol stack! Already running?\n" );
                }
                break;
            case 's':
                switch ( eGetPollingThreadState(  ) )
                {
                case RUNNING:
                    printf( "Protocol stack is running.\n" );
                    break;
                case STOPPED:
                    printf( "Protocol stack is stopped.\n" );
                    break;
                case SHUTDOWN:
                    printf( "Protocol stack is shuting down.\n" );
                    break;
                }
                break;
            case 'h':
                printf( "FreeModbus demo application help:\n" );
                printf( "  'd' ... disable protocol stack.\n" );
                printf( "  'e' ... enabled the protocol stack.\n" );
                printf( "  's' ... show current status.\n" );
                printf( "  'q' ... quit application.\n" );
                printf( "  'i' ... modbus slave information.\n" );
                printf( "  'h' ... this information.\n" );
                printf( "\n" );
                break;
            case 'i':
                printf("Modbus slave information:\n");
                printf("\t> id..........:%d\n", mbSlave.mbId);
                printf("\t> port........:%s\n", mbSlave.mbPort);
                printf("\t> baud-rate...:%ld\n", mbSlave.mbBaud_Rate);
                printf("\t> parity......:");
                if (mbSlave.mbParity == MB_PAR_ODD) {
                    printf("MB_PAR_ODD\n");
                }
                else if (mbSlave.mbParity == MB_PAR_EVEN) {
                    printf("MB_PAR_EVEN\n");
                }
                else {
                    printf("MB_PAR_NONE\n");
                }
                break;
            default:
                if( !bDoExit && ( cCh != '\n' ) )
                {
                    printf( "Invalid command '%c'!\n", cCh );
                }
                break;
            }

            /* eat up everything untill return character. */
            while( !bDoExit && ( cCh != '\n' ) )
            {
                cCh = getchar(  );
            }
        }
        while( !bDoExit );

        printf("\nModbus slave app stop!!\n");

        /* Release hardware resources. */
        ( void )eMBClose(  );
        iExitCode = EXIT_SUCCESS;
    }


    return ( iExitCode );
}

BOOL
bCreatePollingThread( void )
{
    BOOL            bResult;
    pthread_t       xThread;

    if( eGetPollingThreadState(  ) == STOPPED )
    {
        if( pthread_create( &xThread, NULL, pvPollingThread, NULL ) != 0 )
        {
            bResult = FALSE;
        }
        else
        {
            bResult = TRUE;
        }
    }
    else
    {
        bResult = FALSE;
    }

    return bResult;
}

void           *
pvPollingThread( void *pvParameter )
{
    vSetPollingThreadState( RUNNING );

    if( eMBEnable(  ) == MB_ENOERR )
    {
        do
        {
            if( eMBPoll(  ) != MB_ENOERR ) {
                break;
            }
            /******************************
             * @brief USER CODE EXTENSION *
             ******************************/
            serial_port_tracking(mbSlave.mbPort);

            if (mbslave_register_update() < 0) {
                int iDx;
                for (iDx = 0; iDx < 60; ++iDx) {
                    usRegHoldingBuf[iDx] = ( USHORT )mbSLAVE_REG_VALUE_DEFAULT;
                    tmp_usRegHoldingBuf[iDx] = ( USHORT )mbSLAVE_REG_VALUE_DEFAULT;
                }
            }
        }
        while( eGetPollingThreadState(  ) != SHUTDOWN );
    }
    ( void )eMBDisable(  );

    vSetPollingThreadState( STOPPED );

    return 0;
}

enum ThreadState
eGetPollingThreadState(  )
{
    enum ThreadState eCurState;

    ( void )pthread_mutex_lock( &xLock );
    eCurState = ePollThreadState;
    ( void )pthread_mutex_unlock( &xLock );

    return eCurState;
}

void
vSetPollingThreadState( enum ThreadState eNewState )
{
    ( void )pthread_mutex_lock( &xLock );
    ePollThreadState = eNewState;
    ( void )pthread_mutex_unlock( &xLock );
}

eMBErrorCode
eMBRegInputCB( UCHAR * pucRegBuffer, USHORT usAddress, USHORT usNRegs )
{
    eMBErrorCode    eStatus = MB_ENOERR;
    int             iRegIndex;

    if( ( usAddress >= REG_INPUT_START )
        && ( usAddress + usNRegs <= REG_INPUT_START + REG_INPUT_NREGS ) )
    {
        iRegIndex = ( int )( usAddress - usRegInputStart );
        while( usNRegs > 0 )
        {
            *pucRegBuffer++ = ( unsigned char )( usRegInputBuf[iRegIndex] >> 8 );
            *pucRegBuffer++ = ( unsigned char )( usRegInputBuf[iRegIndex] & 0xFF );
            iRegIndex++;
            usNRegs--;
        }
    }
    else
    {
        eStatus = MB_ENOREG;
    }

    return eStatus;
}

eMBErrorCode
eMBRegHoldingCB( UCHAR * pucRegBuffer, USHORT usAddress, USHORT usNRegs, eMBRegisterMode eMode )
{
    eMBErrorCode    eStatus = MB_ENOERR;
    int             iRegIndex;

    if (usAddress >= REG_HOLDING_START) {
        /**
         * @brief REG_HOLDING_ADDR : 40000 - 40060
         *******/
        if( ( usAddress >= REG_HOLDING_START ) &&
            ( usAddress + usNRegs <= REG_HOLDING_START + REG_HOLDING_NREGS ) )
        {
            iRegIndex = ( int )( usAddress - usRegHoldingStart );
            switch ( eMode ) {
                /* Pass current register values to the protocol stack. */
            case MB_REG_READ:
                while( usNRegs > 0 ) {
                    *pucRegBuffer++ = ( UCHAR ) ( usRegHoldingBuf[iRegIndex] >> 8 );
                    *pucRegBuffer++ = ( UCHAR ) ( usRegHoldingBuf[iRegIndex] & 0xFF );
                    iRegIndex++;
                    usNRegs--;
                }
                break;

                /* Update current register values with new values from the
                * protocol stack. */
            case MB_REG_WRITE:
                while( usNRegs > 0 ) {
                    usRegHoldingBuf[iRegIndex] = *pucRegBuffer++ << 8;
                    usRegHoldingBuf[iRegIndex] |= *pucRegBuffer++;
                    iRegIndex++;
                    usNRegs--;
                }
            }
        }
        else {
            eStatus = MB_ENOREG;
        }

    }
    else {
        /**
         * @brief REG_HOLDING_ADDR : 0 - 60
         *******/
        eStatus = MB_ENOERR;
        iRegIndex = 0;

        if( ( usAddress >= subREG_HOLDING_START ) &&
            ( usAddress + usNRegs <= subREG_HOLDING_START + sub_mbSLAVE_REG_NREGS ) )
        {
            iRegIndex = ( int )( usAddress - tmp_usRegHoldingStart );
            switch ( eMode ) {
                /* Pass current register values to the protocol stack. */
            case MB_REG_READ:
                while( usNRegs > 0 ) {
                    *pucRegBuffer++ = ( UCHAR ) ( tmp_usRegHoldingBuf[iRegIndex] >> 8 );
                    *pucRegBuffer++ = ( UCHAR ) ( tmp_usRegHoldingBuf[iRegIndex] & 0xFF );
                    iRegIndex++;
                    usNRegs--;
                }
                break;

                /* Update current register values with new values from the
                * protocol stack. */
            case MB_REG_WRITE:
                while( usNRegs > 0 ) {
                    tmp_usRegHoldingBuf[iRegIndex] = *pucRegBuffer++ << 8;
                    tmp_usRegHoldingBuf[iRegIndex] |= *pucRegBuffer++;
                    iRegIndex++;
                    usNRegs--;
                }
            }
        }
        else {
            eStatus = MB_ENOREG;
        }
    }

    //-- Message request comming ------------------//
    log_msg.reg_mode = eMode;
    log_msg.reg_addr = usAddress;
    log_msg.reg_idx = ( int )( usAddress - usRegHoldingStart );
    log_msg.reg_val = usRegHoldingBuf[log_msg.reg_idx];

    printf("-------------------------------\n");
    printf("| Log message request comming |\n");
    printf("-------------------------------\n");
    printf("\t. Mode:        %s\n", (log_msg.reg_mode == MB_REG_READ ? "Read" : "Write"));
    printf("\t. Reg address: %d\n", log_msg.reg_addr);
    printf("\t. Reg index:   %d\n", log_msg.reg_idx);
    printf("\t. Reg value:   %d\n", log_msg.reg_val);

    save_log_req_message(&log_msg);

    return eStatus;
}


eMBErrorCode
eMBRegCoilsCB( UCHAR * pucRegBuffer, USHORT usAddress, USHORT usNCoils, eMBRegisterMode eMode )
{
    return MB_ENOREG;
}

eMBErrorCode
eMBRegDiscreteCB( UCHAR * pucRegBuffer, USHORT usAddress, USHORT usNDiscrete )
{
    return MB_ENOREG;
}


//------------------------------------------------------------------------------------------------------------//
// USER CODE ADDING IMPLEMENT
//------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------//
int8_t mbslave_flexible_config() {
    FILE *_f_mbSLAVE_INFOtxt;
    char *keyw = NULL;
    
    char path[150];

    memset(path, 0, 150);

    /* Opening file in reading mode */
    _f_mbSLAVE_INFOtxt = fopen(mbSLAVE_FILE_CONFIG_PATH, "r");

    if (NULL == _f_mbSLAVE_INFOtxt) {
        printf("[error] open 'mbSlave_info.cfg'\n");

        return ( RET_NG );
    }

    fread(path, 150, 1, _f_mbSLAVE_INFOtxt);
    fclose( _f_mbSLAVE_INFOtxt );

    /**
     * @brief Parser file config
     ***/
    uint8_t iDx;
    for (iDx = 0; iDx < 150; ++iDx) {
        if (path[iDx] == ' ' || path[iDx] == '\r' || path[iDx] == '\n') {
            path[iDx] = 0;
        }
    }

    /**
     * @brief Get modbus slave [ID]
     ****/
    keyw = &path[0];
    if (strcmp((const char *)(keyw), (const char *)"ID") == 0) {
        keyw += (strlen(keyw) + 1);
        mbSlave.mbId = atoi( keyw );
    }
    else {
        printf("[mbslave_info.cfg] Not-FOUND keyword \"ID\"\n");

        return ( RET_NG );
    }

    /**
     * @brief Get modbus slave [PORT]
     ****/
    keyw += (strlen(keyw) + 1);
    if (strcmp((const char *)(keyw), (const char *)"Serial") == 0) {
        keyw += (strlen(keyw) + 1);

        memcpy((uint8_t *)mbSlave.mbPort, (uint8_t *)keyw, strlen(keyw));

        /* from "port.h" */
        extern UCHAR g_PortOpen[16];
        memcpy((uint8_t *)g_PortOpen, (uint8_t *)keyw, strlen(keyw));
    }
    else {
        printf("[mbslave_info.cfg] Not-FOUND keyword \"Serial\"\n");

        return ( RET_NG );
    }

    /**
     * @brief Get modbus slave [BAUD-RATE]
     ****/
    keyw += (strlen(keyw) + 1);
    if (strcmp((const char *)(keyw), (const char *)"Baud") == 0) {
        keyw += (strlen(keyw) + 1);
        mbSlave.mbBaud_Rate = atoi( keyw );
    }
    else {
        printf("[mbslave_info.cfg] Not-FOUND keyword \"Baud\"\n");

        return ( RET_NG );
    }

    /**
     * @brief Get modbus slave [PARITY]
     ****/
    keyw += (strlen(keyw) + 1);
    if (strcmp((const char *)(keyw), (const char *)"Parity") == 0) {
        keyw += (strlen(keyw) + 1);
        if (strcmp((const char *)(keyw), (const char *)"MB_PAR_ODD") == 0) {
            mbSlave.mbParity = MB_PAR_ODD;
        }
        else if (strcmp((const char *)(keyw), (const char *)"MB_PAR_EVEN") == 0) {
            mbSlave.mbParity = MB_PAR_EVEN;
        }
        else {
            mbSlave.mbParity = MB_PAR_NONE;
        }
    }
    else {
        printf("[mbslave_info.cfg] Not-FOUND keyword \"Parity\"\n");

        return ( RET_NG );
    }

    return ( RET_OK );
}

//------------------------------------------------------------------------------------------------------------//
int8_t mbslave_register_update() {
    FILE *f_BMStxt = NULL;
	char path[50];
    char *reg_val_convert = NULL;

	/* Opening file in reading mode */
    f_BMStxt = fopen(BMS_FILE_PATH, "r");
 
    if (NULL == f_BMStxt) {
        return ( RET_NG );
    }

    /**
     * @brief Put content in file to path array
     **/
    fread(path, 50, 1, f_BMStxt);
    fclose( f_BMStxt );

    /**
     * @brief Parser file BMS.txt
     **/
    uint8_t iDx;
    for (iDx = 0; iDx < 50; ++iDx) {
        if (path[iDx] == ' ' || path[iDx] == '\r' || path[iDx] == '\n') {
            path[iDx] = 0;
        }
    }

    /**
     * @brief mbSLAVE_REG_MOD_INDEX
     **/
    reg_val_convert = &path[0];
    usRegHoldingBuf[mbSLAVE_REG_MOD_INDEX] = ( USHORT )atoi(reg_val_convert);
    tmp_usRegHoldingBuf[mbSLAVE_REG_MOD_INDEX] = ( USHORT )atoi(reg_val_convert);

    /**
     * @brief mbSLAVE_REG_SISTEM_BAR_INDX
     **/
    reg_val_convert += strlen(reg_val_convert) + 1;
    usRegHoldingBuf[mbSLAVE_REG_SISTEM_BAR_INDX] = ( USHORT )(atof(reg_val_convert) * 10);
    tmp_usRegHoldingBuf[mbSLAVE_REG_SISTEM_BAR_INDX] = ( USHORT )(atof(reg_val_convert) * 10);
    
    /**
     * @brief mbSLAVE_REG_SET_BAR_VALUE_INDX
     **/
    reg_val_convert += strlen(reg_val_convert) + 1;
    usRegHoldingBuf[mbSLAVE_REG_SET_BAR_VALUE_INDX] = ( USHORT )(atof(reg_val_convert) * 10);
    tmp_usRegHoldingBuf[mbSLAVE_REG_SET_BAR_VALUE_INDX] = ( USHORT )(atof(reg_val_convert) * 10);

    /**
     * @brief mbSLAVE_REG_TANK_DOLULUK_DEGERI_INDX
     **/
    reg_val_convert += strlen(reg_val_convert) + 1;
    usRegHoldingBuf[mbSLAVE_REG_TANK_DOLULUK_DEGERI_INDX] = ( USHORT )(atoi(reg_val_convert));
    tmp_usRegHoldingBuf[mbSLAVE_REG_TANK_DOLULUK_DEGERI_INDX] = ( USHORT )(atoi(reg_val_convert));

    /**
     * @brief mbSLAVE_REG_ERROR_INDX
     **/
    reg_val_convert += strlen(reg_val_convert) + 1;
    usRegHoldingBuf[mbSLAVE_REG_ERROR_INDX] = ( USHORT )atoi(reg_val_convert);
    tmp_usRegHoldingBuf[mbSLAVE_REG_ERROR_INDX] = ( USHORT )atoi(reg_val_convert);

    /**
     * @brief mbSLAVE_REG_STATUS_INDX
     **/
    reg_val_convert += strlen(reg_val_convert) + 1;
    usRegHoldingBuf[mbSLAVE_REG_STATUS_INDX] = ( USHORT )atoi(reg_val_convert);
    tmp_usRegHoldingBuf[mbSLAVE_REG_STATUS_INDX] = ( USHORT )atoi(reg_val_convert);

    return ( RET_OK );
}

//------------------------------------------------------------------------------------------------------------//
int8_t serial_port_tracking(char *port_name) {
    FILE *fp = NULL;

    char path[15];
    char cmd[20] = "ls ";

    strcat(cmd, port_name);

    fp = popen(cmd, "r");
        
    if (fp == NULL) {
        return ( RET_NG );
    }

    fgets(path, strlen(port_name) + 1, fp);

    /* Serial port disconnect deteced */
    if (strcmp((const char *)path, (const char *)port_name) != 0) {
        printf("[disconnected] %s\n", port_name);
        printf("-> kill app\n");

        pclose(fp);

        /* kill app */
        exit(0);
    }

    pclose(fp);
    memset(path, 0, sizeof(path) / sizeof(path[0]));

    return ( RET_OK );
}

//------------------------------------------------------------------------------------------------------------//
void save_log_req_message(log_msg_info_t *log_msg) {
    time_t current_time;
    FILE *fp_log = NULL;

    const char *echo_msg = (const char *)"-------------------------------\n| Log message request comming |\n-------------------------------\n";

    fp_log = fopen(mbSLAVE_LOG_MSG_REQ_PATH, "w");

	if (fp_log == NULL) {
		printf("[error] Open 'log_req_msg.txt'\n");
		/* HANDEL ERROR */

        return;
	}

	time(&current_time);
	fprintf(fp_log, "%s[%s] id: %d, baud-rate: %d, port: %s, bit-parity: %d\n\t. Mode: %s\n\t. Reg address: %d\n\t. Reg index: %d\n\t. Reg value: %d\n", 
                            echo_msg, 
                            strtok(ctime(&current_time), "\n"),
                            log_msg->mbsl->mbId,
                            log_msg->mbsl->mbBaud_Rate,
                            log_msg->mbsl->mbPort,
                            log_msg->mbsl->mbParity,
                            (log_msg->reg_mode == MB_REG_READ ? "Read" : "Write"),
                            log_msg->reg_addr,
                            log_msg->reg_idx,
                            log_msg->reg_val
                            );

	fclose(fp_log);
}