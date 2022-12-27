/**
 * @file      uaes.c
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     micro-aes API source code. 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces!
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "uaes.h"
#include "udbg.h"
#include "ops.h"

#define UAES_MAX_DATA_LEN   64
#define UAES_MAX_KEY_LEN    32
#define UAES_MAX_BLOCK_LEN  16
#define UAES_MAX_KSCHD_LEN  60

uint8_t trace_msk = 0x00;
static uint8_t uaes_data_buf[UAES_MAX_DATA_LEN+1] = {0};
static uint8_t uaes_key_buf[UAES_MAX_KEY_LEN+1] = {0};

static void   uaes_set_kbr(key_length_t length, size_t *Nk, size_t *Nb, size_t *Nr);
static size_t uaes_find_offset(size_t data_length);
static void   uaes_foward_cipher(size_t data_length, size_t Nk, size_t Nb, size_t Nr);
static void   uaes_inverse_cipher(size_t data_length, size_t Nk, size_t Nb, size_t Nr);

/**
 * @brief Sets trace mask for debugging.
 * @param msk unsigned 8-bit variable expressing debugging options to be enabled.
 * @note If __UAES_DEBUG__ is not defined this function is not available.
 * @return uint8_t Returns current trace mask.
 */
#ifdef __UAES_DEBUG__
uint8_t uaes_set_trace_msk(unsigned char msk)
{
  trace_msk |= msk;
  return trace_msk;
}
#else
uint8_t uaes_set_trace_msk(unsigned char msk)
{
  __asm__("NOP");
  return 0x00;
}
#endif /*__UAES_DEBUG__*/

/**
 * @brief Sets Key-Block-Round combination for given length.
 * @param length  Key/Password length, can be UAES128, UAES192 or UAES256.
 * @param Nk      Key length in 32-bit words
 * @param Nb      Block length in 32-bit words
 * @param Nr      Number of encryption rounds.
 */
static void uaes_set_kbr(key_length_t key_length, size_t *Nk, size_t *Nb, size_t *Nr)
{
  switch (key_length)
  {
    case UAES128:
      *(Nk) = 4;
      *(Nb) = 4;
      *(Nr) = 10;
      break;

    case UAES192:
      *(Nk) = 6;
      *(Nb) = 4;
      *(Nr) = 12;
      break;
    
    case UAES256:
      *(Nk) = 8;
      *(Nb) = 4;
      *(Nr) = 14;
      break;
  
    default:
      UAES_TRACE(UAES_TRACE_MSK_TRACE, "Invalid argument \"length\" was provided. Using 256-bit key length.");
      *(Nk) = 8;
      *(Nb) = 4;
      *(Nr) = 14;
      break;
  }
  return;
}

/**
 * @brief Sets the necessary data offset scalar for encryption/decryption.
 * @param data_length Length of the data to be encrypted.
 * @return size_t Offset number to be used.
 */
static size_t uaes_find_offset(size_t data_length)
{
  size_t offset = 0;
  if( data_length >= 48 )
  {
    offset = 3;
  }
  else if( ( data_length >= 32 ) && ( data_length < 48 ) )
  {
    offset = 2;
  }
  else if( ( data_length >= 16 ) && ( data_length < 32 ) )
  {
    offset = 1;
  }

  return offset;
}

/**
 * @brief Performs foward cipher encryption on provided data.
 * @param data_length Length of the data to be encrypted.
 * @param Nk          Key length in 32-bit words.
 * @param Nb          Block length in 32-bit words.
 * @param Nr          Number of encryption rounds.
 * @return int        If successful returns a 0, otherwise -1 will be returned.
 */
static void uaes_foward_cipher(size_t data_length, size_t Nk, size_t Nb, size_t Nr)
{
  uint8_t  block[UAES_MAX_BLOCK_LEN + 1] = {0};
  uint32_t kschd[UAES_MAX_KSCHD_LEN + 1] = {0};
  size_t offset = 0;
  size_t kdx = 0;
  offset = uaes_find_offset(data_length);

  key_expansion(uaes_key_buf, kschd, Nk, (Nb*(Nr+1)));
  while (kdx < offset)
  {
    memcpy((void *)block, (void *)(&uaes_data_buf[16*kdx]), 4*Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].block = ", block, 0);
    add_round_key(block, kschd, 0, Nb);
    for(size_t round = 1; round < Nr; round++)
    {
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].start = ", block, round);
      sub_block(block, Nb);
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].s_box = ", block, round);
      shift_rows(block, Nb);
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].sh_row = ", block, round);
      mix_columns(block, Nb);
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].m_col = ", block, round);
      add_round_key(block, kschd, round, Nb);
    }
    sub_block(block, Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].s_box = ", block, Nr);
    shift_rows(block, Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].sh_row = ", block, Nr);
    add_round_key(block, kschd, Nr, Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].end = ", block, Nr);
    memcpy((void *)(&uaes_data_buf[16*kdx]), (void *)(block), 4*Nb);
    kdx++;
  }
  return;
}

static void uaes_inverse_cipher(size_t data_length, size_t Nk, size_t Nb, size_t Nr)
{

  return;
}


/**
 * @brief         AES Encryption process.
 * 
 * @param in      Pointer to the NULL terminated input string, with a maximum of 64 characters.
 * @param out     Pointer to the output buffer, must have size equal or greater than the input string. 
 * @param key     Pointer to the NULL terminated key string, with a maximum of 32 characters.
 * @param length  Key length, can be UAES128, UAES192 or UAES256.
 *                If an invalid enumerator is passed, AES-256 is the standard procedure.
 * 
 * @note  If the key provided has a length less than the specified, it will be padded with zeroes.
 * @note  If the key provided has a length greater than the specified, it will be truncated.
 *        
 * @return int If successful returns a 0, otherwise -1 will be returned.
 */
int uaes_encryption(uint8_t* in, uint8_t* out, uint8_t* key, key_length_t key_length)
{
  UAES_TRACE(UAES_TRACE_MSK_TRACE, "Tracing is enabled.");
  
  int err = -1;
  size_t Nk = 0;   
  size_t Nb = 0;
  size_t Nr = 0;
  size_t data_len = 0;
  size_t key_len = 0;

  if( ( NULL == in ) || ( NULL == key ) ||
      ( ( UAESRNG < key_length  ) || ( UAES128 > key_length ) ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Invalid arguments were passed! encryption aborted.");
    return err;
  }
  
  data_len = strlen(in);
  key_len = strlen(key);

  if( ( UAES_MAX_DATA_LEN < data_len ) || ( UAES_MAX_KEY_LEN < key_len ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Input or password string exceeds maximum! encryption aborted.");
    return err;
  }  

  uaes_set_kbr(key_length, &Nk, &Nb, &Nr); 
  memset((void *)uaes_data_buf, 0, UAES_MAX_DATA_LEN + 1);
  memcpy((void *)uaes_data_buf, (void *)in,  data_len);
  memset((void *)uaes_key_buf , 0, UAES_MAX_KEY_LEN + 1);
  memcpy((void *)uaes_key_buf , (void *)key, key_len);
  
  uaes_foward_cipher(data_len, Nk, Nb, Nr);

  memcpy((void *)out, (void *)uaes_data_buf, data_len);
  
  err = 0;

  return err;
}

int uaes_decryption(uint8_t* in, uint8_t* out, uint8_t* key, key_length_t key_length)
{
  UAES_TRACE(UAES_TRACE_MSK_TRACE, "Tracing is enabled.");
  
  int err = -1;
  size_t Nk = 0;   
  size_t Nb = 0;
  size_t Nr = 0;
  size_t data_len = 0;
  size_t key_len = 0;

  if( ( NULL == in ) || ( NULL == key ) ||
      ( ( UAESRNG < key_length  ) || ( UAES128 > key_length ) ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Invalid arguments were passed! encryption aborted.");
    return err;
  }
  
  data_len = strlen(in);
  key_len = strlen(key);

  if( ( UAES_MAX_DATA_LEN < data_len ) || ( UAES_MAX_KEY_LEN < key_len ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Input or password string exceeds maximum! encryption aborted.");
    return err;
  }

  uaes_set_kbr(key_length, &Nk, &Nb, &Nr);
  memset((void *)uaes_data_buf, 0, UAES_MAX_DATA_LEN + 1);
  memcpy((void *)uaes_data_buf, (void *)in,  data_len);
  memset((void *)uaes_key_buf , 0, UAES_MAX_KEY_LEN + 1);
  memcpy((void *)uaes_key_buf , (void *)key, key_len);

  uaes_inverse_cipher(data_len, Nk, Nb, Nr);

  memcpy((void *)out, (void *)uaes_data_buf, data_len);
  
  err = 0;

  return err;
}
