/**
 * @file      uaes.c
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     uAES API source code. 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces!
 *  
 * TODO: Fix segmentation fault when key size does not match encryption type.
 * TODO: Implement a static buffer for key and input in order to perform encryption/decryption operations.
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

#define uAES_HEADER_KEY_MSK 0xFF00
#define uAES_HEADER_SIZE_MSK 0x00FF
#define uAES_MAX_INPUT_SIZE  64UL
#define uAES_MAX_KEY_SIZE    32UL
#define uAES_MAX_BLOCK_SIZE  16UL
#define uAES_MAX_KSCHD_SIZE  60UL

#define uAES_HEADER_GET_KEY_TYPE(h)  (ukey_t)((h & uAES_HEADER_KEY_MSK) >> 8 )
#define uAES_HEADER_GET_SIZE(h)       (size_t)((h & uAES_HEADER_SIZE_MSK) >> 0 )
#define uAES_HEADER_PUT_KEY_TYPE(h, kt)  h |= (uint16_t)(((uint8_t) kt ) << 8 )
#define uAES_HEADER_PUT_SIZE(h, l)        h |= (uint16_t)(((uint8_t) l ) << 0 )

uint8_t trace_msk   = 0x00;
int     debug_line  = 0;

static uint8_t input_buffer[uAES_MAX_INPUT_SIZE] = {0};
static uint8_t key_buffer[uAES_MAX_KEY_SIZE]     = {0};

static size_t uaes_strnlen(char *str, size_t lim);
static void   uaes_set_kbr(ukey_t key_type, size_t *Nk, size_t *Nb, size_t *Nr);
static void   uaes_foward_cipher(uint8_t *data, size_t data_length, uint8_t *key, size_t Nk, size_t Nb, size_t Nr);
static void   uaes_inverse_cipher(uint8_t *data, size_t data_length, uint8_t *key, size_t Nk, size_t Nb, size_t Nr);

/**
 * @brief Sets trace mask for debugging.
 * @param msk unsigned 8-bit variable expressing debugging options to be enabled.
 * @note If __uAES_DEBUG__ is not defined this function is not available.
 * @return uint8_t Returns current trace mask.
 */
#ifdef __uAES_DEBUG__
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
#endif /*__uAES_DEBUG__*/

static size_t uaes_strnlen(char *str, size_t lim)
{
  size_t s = 0;
  if(( NULL != str) && (0 < lim))
  {
    for(s = 0; ((s < lim)&&(str[s] != 0x00)); s++);
  }
  return s;
}

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
      uAES_TRACE(uAES_TRACE_MSK_TRACE, "Invalid argument \"length\" was provided. Using 256-bit key length.");
      *(Nk) = 8;
      *(Nb) = 4;
      *(Nr) = 14;
      break;
  }
  return;
}

/**
 * @brief Computes foward cipher encryption on provided data set.
 * @param data_length Length of the data to be encrypted.
 * @param Nk          Key length in 32-bit words.
 * @param Nb          Block length in 32-bit words.
 * @param Nr          Number of encryption rounds.
 * @return int        If successful returns a 0, otherwise -1 will be returned.
 */
static void uaes_foward_cipher(uint8_t *data, size_t data_length, uint8_t *key, size_t Nk, size_t Nb, size_t Nr)
{
  uint8_t  block[uAES_MAX_BLOCK_SIZE] = {0};
  uint32_t kschd[uAES_MAX_KSCHD_SIZE] = {0};
  size_t offset = ( data_length >> 4 );
  size_t kdx = 0;

  key_expansion(key, kschd, Nk, (Nb*(Nr+1)));
  while (kdx < offset)
  {
    memcpy((void *)block, (void *)(&data[16*kdx]), 4*Nb);
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
    memcpy((void *)(&data[16*kdx]), (void *)(block), 4*Nb);
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
static void uaes_inverse_cipher(uint8_t *data, size_t data_length, uint8_t *key, size_t Nk, size_t Nb, size_t Nr)
{
  uint8_t   block[uAES_MAX_BLOCK_SIZE] = {0};
  uint32_t  kschd[uAES_MAX_KSCHD_SIZE] = {0};
  size_t offset = ( data_length >> 4 );
  size_t kdx = 0;

  key_expansion(key, kschd, Nk, (Nb*(Nr+1)));
  while(kdx < offset)
  {
    memcpy((void *) block, (void *)(&data[16*kdx]), 4*Nb);
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
    memcpy((void *)(&data[16*kdx]), (void *)block, 4*Nb);
    kdx++;
  }
  return;
}

int uaes128enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size)
{
  int err = -1;
  const size_t Nk = 4, Nb = 4, Nr = 10;
  if( (NULL != key) && (NULL != plaintext) && (0 < plaintext_size) )
  {
    err = 0;
    uaes_foward_cipher(plaintext, plaintext_size, key, Nk, Nb, Nr);
  }
  return err;
}

int uaes192enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size)
{
  int err = -1;
  const size_t Nk = 6, Nb = 4, Nr = 12;
  if( (NULL != key) && (NULL != plaintext) && (0 < plaintext_size) )
  {
    err = 0;
    uaes_foward_cipher(plaintext, plaintext_size, key, Nk, Nb, Nr);
  }
  return err;
}

int uaes256enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size)
{
  int err = -1;
  const size_t Nk = 8, Nb = 4, Nr = 14;
  if((NULL != key) && (NULL != plaintext) && (0 < plaintext_size) && (uAES_MAX_INPUT_SIZE > plaintext_size))
  {
    err = 0;
    uaes_foward_cipher(plaintext, plaintext_size, key, Nk, Nb, Nr);
  }
  return err;
}

extern int uaes128dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size)
{
  int err = -1;
  const size_t Nk = 4, Nb = 4, Nr = 10;
  if( (NULL != key) && (NULL != ciphertext) && (0 < ciphertext_size) && (uAES_MAX_INPUT_SIZE > ciphertext_size))
  {
    err = 0;
    uaes_inverse_cipher(ciphertext, ciphertext_size, key, Nk, Nb, Nr);
  }
  return err;
}
extern int uaes192dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size)
{
  int err = -1;
  const size_t Nk = 6, Nb = 4, Nr = 12;
  if( (NULL != key) && (NULL != ciphertext) && (0 < ciphertext_size) )
  {
    err = 0;
    uaes_inverse_cipher(ciphertext, ciphertext_size, key, Nk, Nb, Nr);
  }
  return err;
}
extern int uaes256dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size)
{
  int err = -1;
  const size_t Nk = 8, Nb = 4, Nr = 14;
  if( (NULL != key) && (NULL != ciphertext) && (0 < ciphertext_size) )
  {
    err = 0;
    uaes_inverse_cipher(ciphertext, ciphertext_size, key, Nk, Nb, Nr);
  }
  return err;
}

