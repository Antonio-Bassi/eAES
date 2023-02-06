/**
 * @file      uaes.c
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     uAES API source code. 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces!
 *  
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "uaes.h"
#include "udbg.h"
#include "umem.h"
#include "ops.h"

#define UAES_MAX_DATA_LEN   64
#define UAES_MAX_KEY_LEN    32
#define UAES_MAX_BLOCK_LEN  16
#define UAES_MAX_KSCHD_LEN  60

typedef struct header
{
  ukey_t    key_type;
  size_t    buf_len;
}header_t;

uint8_t trace_msk = 0x00;
static uint8_t uaes_data_buf[UAES_MAX_DATA_LEN+1] = {0};
static uint8_t uaes_key_buf[UAES_MAX_KEY_LEN+1]   = {0};

static void   uaes_set_kbr(ukey_t key_type, size_t *Nk, size_t *Nb, size_t *Nr);
static size_t uaes_align_data_length(size_t data_length);
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
  return 0;
}
#endif /*__UAES_DEBUG__*/

/**
 * @brief Sets Key-Block-Round combination for given length.
 * @param key_type  Key type, can be UAES128, UAES192 or UAES256.
 * @param Nk        Key length in 32-bit words
 * @param Nb        Block length in 32-bit words
 * @param Nr        Number of encryption rounds.
 */
static void uaes_set_kbr(ukey_t key_type, size_t *Nk, size_t *Nb, size_t *Nr)
{
  switch (key_type)
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
 * @brief Aligns data length to be a multiple of the AES block size.
 * @param data_length Length of the data to be encrypted.
 * @return size_t Data length to be used.
 */
static size_t uaes_align_data_length(size_t data_length)
{
  size_t buffer_length = 16;
  if( data_length > 48 )
  {
    buffer_length = 64;
  }
  else if( data_length > 32 )
  {
    buffer_length = 48;
  }
  else if( data_length > 16)
  {
    buffer_length = 32;
  }
  return buffer_length;
}

/**
 * @brief Computes foward cipher encryption on provided data set.
 * @param data_length Length of the data to be encrypted.
 * @param Nk          Key length in 32-bit words.
 * @param Nb          Block length in 32-bit words.
 * @param Nr          Number of encryption rounds.
 * @return int        If successful returns a 0, otherwise -1 will be returned.
 */
static void uaes_foward_cipher(size_t data_length, size_t Nk, size_t Nb, size_t Nr)
{
  uint8_t  block[UAES_MAX_BLOCK_LEN] = {0};
  uint32_t kschd[UAES_MAX_KSCHD_LEN] = {0};
  size_t offset = ( data_length >> 4 );
  size_t kdx = 0;

  key_expansion(uaes_key_buf, kschd, Nk, (Nb*(Nr+1)));
  while (kdx < offset)
  {
    memcpy((void *)block, (void *)(&uaes_data_buf[16*kdx]), 4*Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].block = ", block, (size_t)0);
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

/**
 * @brief Computes inverse cipher decryption on provided data set.
 * @param data_length 
 * @param Nk 
 * @param Nb 
 * @param Nr 
 */
static void uaes_inverse_cipher(size_t data_length, size_t Nk, size_t Nb, size_t Nr)
{
  uint8_t   block[UAES_MAX_BLOCK_LEN] = {0};
  uint32_t  kschd[UAES_MAX_KSCHD_LEN] = {0};
  size_t offset = ( data_length >> 4 );
  size_t kdx = 0;

  key_expansion(uaes_key_buf, kschd, Nk, (Nb*(Nr+1)));
  while(kdx < offset)
  {
    memcpy((void *) block, (void *)(&uaes_data_buf[16*kdx]), 4*Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].block = ", block, Nr);
    add_round_key(block, kschd, Nr, Nb);
    for(size_t round = Nr - 1; round > 0; round--)
    {
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].start = ", block, round);
      inv_shift_rows(block, Nb);
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].inv_sh_row = ", block, round);
      inv_sub_block(block, Nb);
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].inv_s_box = ", block, round);
      add_round_key(block, kschd, round, Nb);
      UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].add_rkey = ", block, round);
      inv_mix_columns(block, Nb);
    }
    inv_shift_rows(block, Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].inv_sh_row = ", block, (size_t)0);
    inv_sub_block(block, Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_INV, "round[%lu].inv_s_box = ", block, (size_t)0);
    add_round_key(block, kschd, 0, Nb);
    UAES_TRACE_BLOCK(UAES_TRACE_MSK_FWD, "round[%lu].end = ", block, (size_t)0);
    memcpy((void *)(&uaes_data_buf[16*kdx]), (void *)block, 4*Nb);
    kdx++;
  }
  return;
}

/**
 * @brief         AES Encryption process.
 * 
 * @param in      Pointer to a NULL terminated input string, with a maximum of 64 characters.
 * @param key     Pointer to a NULL terminated password string, with a maximum of 32 characters.
 * @param length  Key type, can be UAES128, UAES192 or UAES256.
 *                If an invalid enumerator is passed, AES-256 key type encryption is the standard procedure.
 * 
 * @note  If the key provided has a length less than the specified, it will be padded with zeroes.
 * @note  If the key provided has a length greater than the specified, it will be truncated.
 *        
 * @return uint8_t pointer to the enciphered buffer.
 */
uint8_t* uaes_encryption(uint8_t* in, uint8_t* pwrd, ukey_t key_type)
{
  UAES_TRACE(UAES_TRACE_MSK_TRACE, "Tracing is enabled.");
  
  int err = -1;
  size_t Nk = 0;   
  size_t Nb = 0;
  size_t Nr = 0;
  size_t data_len = 0;
  size_t pwrd_len = 0;

  if( ( NULL == in ) || ( NULL == pwrd ) ||
      ( ( UAESRNG < key_type ) || ( UAES128 > key_type ) ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Invalid arguments were passed! encryption aborted.");
    return err;
  }
  
  data_len = strlen(in);
  pwrd_len = strlen(pwrd);

  if( ( UAES_MAX_DATA_LEN < data_len ) || ( UAES_MAX_KEY_LEN < pwrd_len ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Input or password string exceeds maximum! encryption aborted.");
    return err;
  }  

  uaes_set_kbr(key_type, &Nk, &Nb, &Nr); 
  memset((void *)uaes_data_buf, 0, UAES_MAX_DATA_LEN + 1);
  memcpy((void *)uaes_data_buf, (void *)in,  data_len);
  memset((void *)uaes_key_buf , 0, UAES_MAX_KEY_LEN + 1);
  memcpy((void *)uaes_key_buf , (void *)pwrd, pwrd_len);
  
  data_len = uaes_align_data_length(data_len);

  uaes_foward_cipher(data_len, Nk, Nb, Nr);

  err = data_len;
  return err;
}

uint8_t* uaes_decryption(uint8_t* in, uint8_t* pwrd, ukey_t key_type)
{
  UAES_TRACE(UAES_TRACE_MSK_TRACE, "Tracing is enabled.");
  
  int err = -1;
  size_t Nk = 0;   
  size_t Nb = 0;
  size_t Nr = 0;
  size_t data_len = 0;
  size_t pwrd_len = 0;

  if( ( NULL == in ) || ( NULL == pwrd ) ||
      ( ( UAESRNG < key_type  ) || ( UAES128 > key_type ) ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Invalid arguments were passed! encryption aborted.");
    return err;
  }
  
  data_len  = strlen(in);
  pwrd_len  = strlen(pwrd);

  if( ( UAES_MAX_DATA_LEN < data_len ) || ( UAES_MAX_KEY_LEN < pwrd_len ) )
  {
    UAES_TRACE(UAES_TRACE_MSK_INPUT, "Input or password string exceeds maximum! encryption aborted.");
    return err;
  }

  uaes_set_kbr(key_type, &Nk, &Nb, &Nr);
  memset((void *)uaes_data_buf, 0, UAES_MAX_DATA_LEN + 1);
  memcpy((void *)uaes_data_buf, (void *)in,  data_len);
  memset((void *)uaes_key_buf , 0, UAES_MAX_KEY_LEN + 1);
  memcpy((void *)uaes_key_buf , (void *)pwrd, pwrd_len);

  data_len = uaes_align_data_length(data_len);
  
  uaes_inverse_cipher(data_len, Nk, Nb, Nr);
  
  err = 0;

  return err;
}
