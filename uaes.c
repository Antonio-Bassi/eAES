/**ES_MAX_KEY_LEN
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

#define uAES_MAX_INPUT_LEN  64
#define uAES_MAX_KEY_LEN    32
#define uAES_MAX_BLOCK_LEN  16
#define uAES_MAX_KSCHD_LEN  60

typedef struct header
{
  ukey_t    key_type;
  size_t    buf_len;
}header_t;

static const size_t header_size = sizeof(header_t);
static uint8_t uaes_cipher_buf[uAES_MAX_INPUT_LEN]  = {0};
static uint8_t uaes_key_buf[uAES_MAX_KEY_LEN]       = {0};

uint8_t trace_msk   = 0x00;
int     debug_line  = 0;

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
    case uAES128:
      *(Nk) = 4;
      *(Nb) = 4;
      *(Nr) = 10;
      break;

    case uAES192:
      *(Nk) = 6;
      *(Nb) = 4;
      *(Nr) = 12;
      break;
    
    case uAES256:
      *(Nk) = 8;
      *(Nb) = 4;
      *(Nr) = 14;
      break;
  
    default:
      UAES_TRACE(uAES_TRACE_MSK_TRACE, "Invalid argument \"length\" was provided. Using 256-bit key length.");
      *(Nk) = 8;
      *(Nb) = 4;
      *(Nr) = 14;
      break;
  }
  return;
}

/**
 * @brief Aligns input length to be a multiple of the AES block size.
 * @param data_length Length of the data to be encrypted.
 * @return size_t Buffer length to be used.
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
  uint8_t  block[uAES_MAX_BLOCK_LEN] = {0};
  uint32_t kschd[uAES_MAX_KSCHD_LEN] = {0};
  size_t offset = ( data_length >> 4 );
  size_t kdx = 0;

  key_expansion(uaes_key_buf, kschd, Nk, (Nb*(Nr+1)));
  while (kdx < offset)
  {
    memcpy((void *)block, (void *)(&uaes_cipher_buf[16*kdx]), 4*Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].block = ", block, (size_t)0);
    add_round_key(block, kschd, 0, Nb);
    for(size_t round = 1; round < Nr; round++)
    {
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].start = ", block, round);
      sub_block(block, Nb);
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].s_box = ", block, round);
      shift_rows(block, Nb);
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].sh_row = ", block, round);
      mix_columns(block, Nb);
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].m_col = ", block, round);
      add_round_key(block, kschd, round, Nb);
    }
    sub_block(block, Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].s_box = ", block, Nr);
    shift_rows(block, Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].sh_row = ", block, Nr);
    add_round_key(block, kschd, Nr, Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].end = ", block, Nr);
    memcpy((void *)(&uaes_cipher_buf[16*kdx]), (void *)(block), 4*Nb);
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
  uint8_t   block[uAES_MAX_BLOCK_LEN] = {0};
  uint32_t  kschd[uAES_MAX_KSCHD_LEN] = {0};
  size_t offset = ( data_length >> 4 );
  size_t kdx = 0;

  key_expansion(uaes_key_buf, kschd, Nk, (Nb*(Nr+1)));
  while(kdx < offset)
  {
    memcpy((void *) block, (void *)(&uaes_cipher_buf[16*kdx]), 4*Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].block = ", block, Nr);
    add_round_key(block, kschd, Nr, Nb);
    for(size_t round = Nr - 1; round > 0; round--)
    {
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].start = ", block, round);
      inv_shift_rows(block, Nb);
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].inv_sh_row = ", block, round);
      inv_sub_block(block, Nb);
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].inv_s_box = ", block, round);
      add_round_key(block, kschd, round, Nb);
      uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].add_rkey = ", block, round);
      inv_mix_columns(block, Nb);
    }
    inv_shift_rows(block, Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].inv_sh_row = ", block, (size_t)0);
    inv_sub_block(block, Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_INV, "round[%lu].inv_s_box = ", block, (size_t)0);
    add_round_key(block, kschd, 0, Nb);
    uAES_TRACE_BLOCK(uAES_TRACE_MSK_FWD, "round[%lu].end = ", block, (size_t)0);
    memcpy((void *)(&uaes_cipher_buf[16*kdx]), (void *)block, 4*Nb);
    kdx++;
  }
  return;
}

/**
 * @brief         AES Encryption process.
 * 
 * @param in      Pointer to a NULL terminated input string, with a maximum of 64 characters.
 * @param key     Pointer to a NULL terminated password string, with a maximum of 32 characters.
 * @param length  Key type, can be uAES128, uAES192 or uAES256.
 *                If an invalid enumerator is passed, AES-256 key type encryption is the standard procedure.
 * @return uint8_t pointer to the encrypted buffer.
 */
uint8_t* uaes_encryption(uint8_t* in, uint8_t* key, ukey_t key_type)
{
  uAES_TRACE(uAES_TRACE_MSK_TRACE, "Tracing is enabled.");
  header_t header = {0};
  size_t Nk = 8, Nb = 4, Nr = 14;
  uint8_t *cipher = NULL;
  uint8_t *cipher_txt = NULL;
  size_t total_length = 0;

  if( ( NULL == in ) || ( NULL == key ) )
  {
    uAES_TRACE(uAES_TRACE_MSK_INPUT, "Null pointers were passed as arguments! Aborted.");
    return cipher;
  }
  
  size_t input_length = strlen(in);
  size_t key_length   = strlen(key);

  if( ( uAES_MAX_INPUT_LEN < input_length ) || 
      ( uAES_MAX_KEY_LEN < key_length) )
  {
    uAES_TRACE(uAES_TRACE_MSK_INPUT, "String arguments exceeded the maximum size! Aborted.");
    return cipher;
  }

  uaes_set_kbr(key_type, &Nk, &Nb, &Nr);
  total_length  = uaes_align_data_length(input_length);
  total_length += header_size;

  cipher = (uint8_t *) prv_malloc(total_length);

  if( NULL == cipher )
  {
    uAES_TRACE(uAES_TRACE_MSK_MEM, "String arguments exceeded the maximum size! Aborted.");
    return cipher;
  }

  cipher_txt = cipher + header_size;
  header.key_type = key_type;
  header.buf_len = input_length;

  memset(cipher, 0x00, total_length);
  memcpy((void *)cipher, (void *) &header, sizeof(header_t));
  memcpy((void *)uaes_cipher_buf, (void *)in, input_length);
  memcpy((void *)uaes_key_buf, (void *)key, key_length);

  uaes_foward_cipher(input_length, Nk, Nb, Nr);

  memcpy((void *)cipher_txt, (void *)uaes_cipher_buf, input_length);

  return cipher;
}

uint8_t* uaes_decryption(uint8_t* in, uint8_t* key, ukey_t key_type)
{
  uAES_TRACE(uAES_TRACE_MSK_TRACE, "Tracing is enabled.");
  uint8_t *data;

  return data;
}
