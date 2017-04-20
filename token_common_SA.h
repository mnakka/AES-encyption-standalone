// ========================================================================================================
// ========================================================================================================
// ******************************************** token_common.h ********************************************
// ========================================================================================================
// ========================================================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>  


/******************************** DEFINES ***********************************/
#define OUT_CP_RESET 31
#define OUT_CP_HANDSHAKE 24

#define OUT_CP_DTO_DATA_READY 20
#define OUT_CP_DTO_RESTART 19
#define OUT_CP_DTO_VEC_LOADED 18
#define OUT_CP_DTI_DONE_READING 17
#define OUT_CP_DTI_RESTART 16

#define OUT_CP_START_ENCRYPTION 22

#define IN_SM_READY 31
#define IN_SM_DTI_DATA_READY 30
#define IN_SM_DTO_DONE_READING 29

#define IN_SM_HANDSHAKE 28

// GPIO 0
#define GPIO_0_BASE_ADDR 0x41200000
#define CTRL_DIRECTION_MASK 0x00
#define DATA_DIRECTION_MASK 0xFFFFFFFF


/* Register Offset Definitions */
#define XGPIO_DATA_OFFSET   (0x0)	/* Data register  */
#define XGPIO_TRI_OFFSET    (0x4)	/* I/O direction register  */

#define XGPIO_CHANNEL_OFFSET	0x8
