// ========================================================================================================
// ========================================================================================================
// ****************************************** token_encryption.c ******************************************
// ========================================================================================================
// ========================================================================================================

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>  
//#include <sys/mman.h>

#include "xparameters.h"
#include "xgpio.h"
#include "xstatus.h"
#include "xil_printf.h"


XGpio GPIO_0;
XGpio_Config GPIO_0_conf;

#include "token_common_SA.h"
#define GPIO_DEVICE_ID XPAR_AXI_GPIO_0_DEVICE_ID

// ========================================================================================================
// ========================================================================================================
// Carry out an example encryption using either a hardcoded key ('user_or_PUF_key' = 0) AES key or the 
// PUF key generated and stored in the key register within the VHDL before this routine is called.

#define AES_KEY_LEN_BITS 128
#define AES_PLAINTEXT_LEN_BITS 128
#define AES_CIPHERTEXT_LEN_BITS 128

#define AES_KEY_LEN_BYTES 16
#define AES_PLAINTEXT_LEN_BYTES 16
#define AES_CIPHERTEXT_LEN_BYTES 16

#define DATA_TRANSFER_CHUNK_SIZE_BITS 16

void DoTrialEncryption(int max_str_length, volatile unsigned int *CtrlRegA, volatile unsigned int *DataRegA, 
   int ctrl_mask)
   {
   int word_num, bit_len, iter_num, num_iters;
   unsigned char cipher_out[16];
   unsigned char *vec_ptr;
   int vec_val_chunk; 
   int i;

// 128-bit user-specified (hardcoded) key:
  unsigned char key[AES_KEY_LEN_BYTES] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
   //unsigned char key[AES_KEY_LEN_BYTES] = {
      //0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };

// Plaintext:
//   unsigned char plaintext[AES_PLAINTEXT_LEN_BYTES] = { 
//      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
//      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
//      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
//      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10, 
//   unsigned char plaintext[AES_PLAINTEXT_LEN_BYTES] = { 
//      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
   unsigned char plaintext[AES_PLAINTEXT_LEN_BYTES] = "Wenjie is GREAT\0";

   printf("ECB-BASED ENCRYPTION EXAMPLE:\t");
   printf("USER-SPECIFIED KEY\n\n"); 
   fflush(stdout);

// Print plaintext and key (High order to low order for http://extranet.cryptomathic.com/aescalc)
   printf("PlainText (high order to low order as needed by website version):\n\t");
   for( i = AES_PLAINTEXT_LEN_BYTES-1; i >= 0; i-- )
      { printf("%02X", plaintext[i]); }
   printf("\n");fflush(stdout);

   printf("KEY (high order to low order as needed by website version):\n\t");
   for( i = AES_KEY_LEN_BYTES-1; i >= 0; i-- )
      { printf("%02X", key[i]); }
   printf("\n");fflush(stdout);
   //Execution stops here?? Don't know why

// MUST DO A RESET HERE SINCE the PUF was run above and the key is FIXED after it is run and cannot be changed.
// Resetting allows the user to write a key into the VHDL Key register, otherwise this is prevented.


   *CtrlRegA = ctrl_mask | (1 << OUT_CP_RESET);
   XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);
   *CtrlRegA = ctrl_mask;
   XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

   usleep(10000);

   xil_printf("check a\n\n"); fflush(stdout);

// Wait for READY.
   xil_printf("\n******* Starting Encryption Engine\n"); fflush(stdout);
   if ( ((XGpio_DiscreteRead(&GPIO_0,1) & (1 << IN_SM_READY)) == 0 ))
      { xil_printf("\t\tERROR: Encryption Engine is NOT ready!\n"); fflush(stdout); exit(EXIT_FAILURE); }
   else
      { xil_printf("\t\tHARDWARE IS READY!\n"); fflush(stdout); }

// Reset the VHDL pointers to the vector buffers. 
   *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTO_RESTART);
   XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);
   *CtrlRegA = ctrl_mask;
   XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

   num_iters = 2;

// Once for plaintext and (optionally) once for key
//   printf("\t\tLoading PlainText and Key!\n"); fflush(stdout);
   for ( iter_num = 0; iter_num < num_iters; iter_num++ )
      {
  
// Set size of data transfer.
      if ( iter_num == 0 )
         bit_len = AES_PLAINTEXT_LEN_BITS;
      else
         bit_len = AES_KEY_LEN_BITS;

// Iterate 8 times (transfer 2 bytes at a time).
      for ( word_num = 0; word_num < bit_len/DATA_TRANSFER_CHUNK_SIZE_BITS; word_num++ )
         {

// Add 2 bytes at a time to the pointer. In binary, there are only 16 bytes for plaintext and key
         if ( iter_num == 0 )
            vec_ptr = plaintext + word_num*2;
         else
            vec_ptr = key + word_num*2;

//printf("LoadVecPairMask(): vec_ptr pointer '%s'!\n", vec_ptr); fflush(stdout);
         vec_val_chunk = (vec_ptr[1] << 8) + vec_ptr[0]; 

xil_printf("LoadVecPairMask(): 16-bit binary value in hex '%04X'\n", vec_val_chunk); fflush(stdout);

// Four step protocol
// 1) Assert 'dataXGpio_Out32_ready' while putting the 16-bit binary value on the low order bits of CtrlReg
//printf("LoadVecPairMask(): Writing 'data_ready' with 16-bit binary value in hex '%04X'\n", vec_val_chunk); fflush(stdout);
         *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTO_DATA_READY) | vec_val_chunk;
         XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

// 2) Wait for 'done_reading to go to 1 (it is low by default). State machine latches data in 2 clk cycles. 
//    Maintain 1 on 'data_ready' and continue to hold 16-bit binary chunk.
//printf("LoadVecPairMask(): Waiting state machine 'done_reading' to be set to '1'\n"); fflush(stdout); while ( (*DataRegA & (1 << IN_SM_DTO_DONE_READING)) == 0 );
         while ( (XGpio_DiscreteRead(&GPIO_0,1) & (1 << IN_SM_DTO_DONE_READING)) == 0 );

// 3) Once 'done_reading' goes to 1, set 'data_ready' to 0 and remove chunk;
//printf("LoadVecPairMask(): De-asserting 'data_ready'\n"); fflush(stdout);
         *CtrlRegA = ctrl_mask;
         XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

// 4) Wait for 'done_reading to go to 0.
//printf("LoadVecPairMask(): Waiting state machine 'done_reading' to be set to '0'\n"); fflush(stdout);

         //while ( (*DataRegA & (1 << IN_SM_DTO_DONE_READING)) != 0 );
         while ( (XGpio_DiscreteRead(&GPIO_0,1) &(1 << IN_SM_DTO_DONE_READING))!=0);



//printf("LoadVecPairMask(): Done handshake associated with vector chunk transfer\n"); fflush(stdout);
         }
      }
   xil_printf("\t\tDone loading PlainText and Key!\n"); fflush(stdout);


// ===================================================================================================
   int sam_num, num_sams;
   num_sams = 100;
   for ( sam_num = 0; sam_num < num_sams; sam_num++ )
      {
      *CtrlRegA = ctrl_mask | (1 << OUT_CP_START_ENCRYPTION);
      XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

      //usleep(1);
      *CtrlRegA = ctrl_mask;
      XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);


// Sanity check. Wait for encryption engine to finish.
      //while ( (*DataRegA & (1 << IN_SM_READY)) == 0 );
      while ( (XGpio_DiscreteRead(&GPIO_0,1) &(1 << IN_SM_READY)) ==0);

// Reset the PN value pointers in the VHDL code for transferring the ciphertext to the C program
      *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTI_RESTART); 
      XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);
      *CtrlRegA = ctrl_mask; 
      XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

//printf("GenGetTimingVals(): Checking 'data_ready' of DataTransferOut!\n"); fflush(stdout);

// Wait for 'data_ready' to become 1 after the pointer reset (should already be 1).
      //while ( (*DataRegA & (1 << IN_SM_DTI_DATA_READY)) == 0 );
      while ( (XGpio_DiscreteRead(&GPIO_0,1) &(1 << IN_SM_DTI_DATA_READY))== 0);
      i = 0;
      for ( word_num = 0; word_num < AES_CIPHERTEXT_LEN_BITS/DATA_TRANSFER_CHUNK_SIZE_BITS; word_num++ )
         {

// Read and print a word of ciphertext;
         cipher_out[i] = (unsigned char)(XGpio_DiscreteRead(&GPIO_0,1) & 0x000000FF);
         i++;
         cipher_out[i] = (unsigned char)((XGpio_DiscreteRead(&GPIO_0,1) & 0x0000FF00) >> 8);
         i++;

// Four phases here.
// 1) Got timing value above, indicate we are done reading.
         *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTI_DONE_READING); 
         XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);


// 2) Wait for 'data_ready' to become 0.
         //while ( (*DataRegA & (1 << IN_SM_DTI_DATA_READY)) != 0 );
         while ( (XGpio_DiscreteRead(&GPIO_0,1) &(1 << IN_SM_DTI_DATA_READY))!=0);

// 3) Reset done_reading to 0
         *CtrlRegA = ctrl_mask; 
         XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

// 4) Wait for 'data_ready' to become 1.
         //while ( (*DataRegA & (1 << IN_SM_DTI_DATA_READY)) == 0 );
         while ( (XGpio_DiscreteRead(&GPIO_0,1) &(1 << IN_SM_DTI_DATA_READY)) == 0);

         }
      xil_printf("check c \n");

// Print high order to low order
      printf("Ciphertext (high order encryption to low order as needed by website version):\tIteration %d\n\t", sam_num);
      for( i = AES_CIPHERTEXT_LEN_BYTES-1; i >= 0; i-- )
         printf("%02X", cipher_out[i]);
      printf("\n\n");

      printf("******* Waiting for Encryption Engine to finish\n"); fflush(stdout);
      if ( (XGpio_DiscreteRead(&GPIO_0,1) & (1 << IN_SM_READY)) == 0 )
         { printf("\t\tERROR: Encryption Engine is NOT ready!\n"); fflush(stdout); exit(EXIT_FAILURE); }
      else
         { printf("\t\tEncryption FINISHED!\n"); fflush(stdout); }

// Allow scope to get ready for next sample.
      usleep(1000000);
      }

   return;
   }



// ============================================================================
// ============================================================================
#define MAX_STRING_LEN 2000
#define XGpio_WriteReg(BaseAddress, RegOffset, Data)   XGpio_Out32((BaseAddress) + (RegOffset), (u32)(Data))
int main(int argc, char *argv[])
   {
   volatile unsigned int *CtrlRegA;
   volatile unsigned int *DataRegA;
   unsigned int ctrl_mask;


// ======================================================================================================================
// COMMAND LINE
// ======================================================================================================================
   /*if ( argc != 1 )
      {
      printf("ERROR: token_encryption.elf():\n"); fflush(stdout);
      exit(EXIT_FAILURE);
      }*/

// Open up the memory mapped device so we can access the GPIO registers.
   //int fd = open("/dev/mem", O_RDWR|O_SYNC);

   //if (fd < 0)
      //{ fprintf(stderr, "ERROR: /dev/mem could NOT be opened!\n"); exit(EXIT_FAILURE); }

// Add 2 for the DataReg (for an offset of 8 bytes for 32-bit integer variables)
  // DataRegA = mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPIO_0_BASE_ADDR);
// fd doesn't exist anymore because we are not using memory mapping9*
   xil_printf("check 0 \n");
   CtrlRegA = DataRegA + 2;
   xil_printf("check 1 \n");





   //DataRegA = xgpio_readreg(mm_gc->regs + XGPIO_DATA_OFFSET +
   			  //  xgpio_regoffset(chip, gpio));
   //
   GPIO_0_conf.BaseAddress = XPAR_GPIO_0_BASEADDR;
   GPIO_0_conf.DeviceId = XPAR_AXI_GPIO_0_DEVICE_ID;
   GPIO_0_conf.IsDual = XPAR_AXI_GPIO_0_IS_DUAL;
   XGpio_CfgInitialize(&GPIO_0,&GPIO_0_conf,GPIO_0_conf.BaseAddress);
   //init_platform();


   // Do a hardware reset
   *CtrlRegA = (1 << OUT_CP_RESET);
   xil_printf("check 2 \n");

   XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);
   xil_printf("check 3 \n");

   *CtrlRegA = 0;
   XGpio_DiscreteWrite(&GPIO_0,2,*CtrlRegA);

   usleep(10000);

   ctrl_mask = 0;
   xil_printf("check 4 \n");

   DoTrialEncryption(MAX_STRING_LEN, CtrlRegA, DataRegA, ctrl_mask);
  
   return 0;
   }
