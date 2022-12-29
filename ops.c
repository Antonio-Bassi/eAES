/**
 * @file      uaes_ops.c
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     Source code for the 256-element galois field mathematical operators and cipher operations.
 * @version   0.0
 * @date      2022-12-25
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces!
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "udbg.h"
#include "ops.h"

#define UAES_MAX_BLOCK_LEN  16

static const uint8_t  s_box_fwd_map       = 0x63;
static const uint8_t  s_box_inv_map       = 0x05;
static const uint16_t rijndael_polynomial = 0x11B;

static inline uint32_t rotword(uint32_t word);
static inline uint32_t word_shift(uint32_t word, size_t nshifts);
static inline uint32_t inv_word_shift(uint32_t word, size_t nshifts);
static inline uint8_t  circ_shift(uint8_t byte, size_t nshifts);
static inline uint8_t  inv_circ_shift(uint8_t byte, size_t nshifts);
static uint8_t  gf256_mul(uint8_t Na, uint8_t Nb);
static uint8_t  gf256_inv(uint8_t Na);
static uint32_t rcon(uint8_t val);
static uint8_t  sub_bytes(uint8_t byte);
static uint32_t sub_word(uint32_t word);

/**
 * @brief           Performs word rotation operation on given 32-bit variable.
 * @param word      32-bit variable
 * @return uint32_t Rotated 32-bit word.
 */
static inline uint32_t rotword(uint32_t word)
{
  return ( word >> 8 ) | ( word << 24 );
}

/**
 * @brief           Performs a cyclical byte shift operation on given 32-bit variable.
 * @param word      32-bit variable
 * @param nshifts   Number of desired shifts.
 * @return uint32_t Cyclical-shifted 32-bit variable.
 */
static inline uint32_t word_shift(uint32_t word, size_t nshifts)
{
  return ( ( word >> 8 * nshifts ) | ( word << ( 32 - 8 * nshifts ) ) );
}

/**
 * @brief           Performs an inverse cyclical byte shift operation on 32-bit variable.
 * @param word      32-bit variable.
 * @param nshifts   Number of desired shifts.
 * @return uint32_t Inverse cyclical-shifted 32-bit variable.
 */
static inline uint32_t inv_word_shift(uint32_t word, size_t nshifts)
{
  return ( ( word << 8 * nshifts ) | ( word >> ( 32 - 8 * nshifts ) ) );
}

/**
 * @brief           Performs a circular bit-shift operation on given byte.
 * @param byte      Byte variable.
 * @param nshifts   Number of desired shifts.
 * @return uint8_t  Shifted byte.
 */
static inline uint8_t circ_shift(uint8_t byte, size_t nshifts)
{
  return ( byte << nshifts ) | ( byte >> ( 8 - nshifts ) );
}

/**
 * @brief           Performs an inverse circular bit-shift operation on given byte.
 * @param byte      Byte variable. 
 * @param nshifts   Number of desired shifts.
 * @return uint8_t  Inverse shifted byte.
 */
static inline uint8_t inv_circ_shift(uint8_t byte, size_t nshifts)
{
  return ( ( byte >> nshifts ) | ( byte << ( 8 - nshifts ) ) );
}

/**
 * @brief           Computes the 256-element Galois Field multiplication on given unsigned 8-bit numbers. 
 * @param Na        Unsigned 8-bit number.
 * @param Nb        Unsigned 8-bit number.
 * @return uint8_t  Multiplication result.
 */
static uint8_t gf256_mul(uint8_t Na, uint8_t Nb)
{
  uint8_t prod = 0x00;
  while( ( Na != 0 ) && ( Nb != 0 ) )
  {
    if( Nb & 0x01 )
    {
      prod ^= Na;
    }
    if( Na & 0x80 )
    {
      Na = ( Na << 1 ) ^ rijndael_polynomial;
    }
    else
    {
      Na <<= 1;
    }
    Nb >>= 1;
  }
  return prod;
}

/**
 * @brief           Computes the inverse multiplier of a given unsigned 8-bit number.
 * @param Na        Unsigned 8-bit number.
 * @return uint8_t  Inverse multiplier. 
 */
static uint8_t gf256_inv(uint8_t Na)
{
  if(Na == 0)
    return Na;

  uint8_t Ninv = 1;
  for(Ninv = 1; Ninv < rijndael_polynomial; Ninv++)
  {
    if( (gf256_mul(Na % rijndael_polynomial, Ninv % rijndael_polynomial) % rijndael_polynomial) == 1 )
      break;
  }
  return Ninv;
}

/**
 * @brief           Computes round constant for key expansion algorithm.
 * @param val       Indexed value.
 * @return uint32_t Round constant
 */
static uint32_t rcon(uint8_t val)
{
  if( val == 9 )
    return 0x1b;
  else if( val == 10 )
    return 0x36;
  else
    return ( 0x01 << ( val - 1 ) );
}

/**
 * @brief           Computes sub-bytes transform on given byte variable. 
 * @param byte      Byte variable
 * @return uint8_t  Mapped byte.
 */
static uint8_t sub_bytes(uint8_t byte)
{
  uint8_t sbyte = gf256_inv(byte);
  sbyte = ( sbyte ^ circ_shift(sbyte, 1) ^ circ_shift(sbyte, 2) ^ circ_shift(sbyte, 3) ^ circ_shift(sbyte, 4) ) ^ s_box_fwd_map;
  return sbyte;
}

/**
 * @brief           Computes the inverse sub-bytes transform on given byte variable.
 * @param sbyte     Byte variable (MUST have been previously mapped by sub-bytes transform).
 * @return uint8_t  Re-mapped byte.
 */
static uint8_t inv_sub_bytes(uint8_t sbyte)
{
  uint8_t byte = ( circ_shift(sbyte, 1) ^ circ_shift(sbyte, 3) ^ circ_shift(sbyte, 6) ) ^ s_box_inv_map;
  byte = gf256_inv(byte);
  return byte;
}

/**
 * @brief           Computes the sub-bytes transform on each byte of the given 32-bit word.
 * @param word      32-bit word variable.
 * @return uint32_t Mapped 32-bit word.
 */
static uint32_t sub_word(uint32_t word)
{
  uint8_t  tmp = 0;
  uint32_t s_word = 0;
  size_t idx = 0;

  while( idx < 4 )
  {
    tmp = ( uint8_t )( ( word ) >> ( idx*8 ) );
    tmp = sub_bytes(tmp);
    s_word |= ( ( uint32_t )( tmp ) ) << ( idx*8 );
    idx++;
  }
  return s_word;
}

/**
 * @brief       Computes the sub-bytes transform on each byte of the given data block.
 * @param block Pointer to the first element from the data block array.  
 * @param Nb    Number of 32-bit words present on data block array.
 */
void sub_block(uint8_t *block, size_t Nb)
{
  for(size_t idx = 0; idx < 4*Nb; idx++)
  {   
    block[idx] = sub_bytes(block[idx]);
  }
  return;
}

/**
 * @brief       Computes the inverse sub-bytes transform on each byte of the given data block.
 * @param block Pointer to the first element from the data block array.
 * @param Nb    Number of 32-bit words present on data block array.
 */
void inv_sub_block(uint8_t *block, size_t Nb)
{
  for(size_t idx = 0; idx < 4*Nb; idx++)
  {   
    block[idx] = inv_sub_bytes(block[idx]);
  }
  return;
}

/**
 * @brief         Computes the shift-rows operation on given data block.
 * @param block   Pointer to the first element from the data block array.
 * @param Nb      Number of 32-bit words present on data block array.
 */
void shift_rows(uint8_t *block, size_t Nb)
{   
  uint32_t tmp = 0;
  for(size_t C = 0; C < Nb; C++)
  {
    tmp = (uint32_t)( block[C] | block[C + 4] << 8 | block[C + 8] << 16 | block[C + 12] << 24 );
    tmp = word_shift(tmp, C);    
    for(size_t R = 0; R < Nb; R++)
    {
        block[C + 4*R] = ( uint8_t )( tmp >> 8*R );
    }     
  }
  return;
}

/**
 * @brief       Computes the inverse shift-rows operation on given data block.
 * @param block Pointer to the first element from the data block array.
 * @param Nb    Number of 32-bit words present on data block array.
 */
void inv_shift_rows(uint8_t *block, size_t Nb)
{
  uint32_t tmp = 0;
  for(size_t C = 0; C < Nb; C++)
  {
    tmp = (uint32_t)( block[C] | block[C + 4] << 8 | block[C + 8] << 16 | block[C + 12] << 24 );
    tmp = inv_word_shift(tmp, C);   
    for(size_t R = 0; R < Nb; R++)
    {
        block[C + 4*R] = ( uint8_t )( tmp >> 8*R );
    }     
  }
  return;
}

/**
 * @brief       Computes the mix-columns operation on given data block.
 * @param block Pointer to the first element from the data block array.
 * @param Nb    Number of 32-bit words present on data block array. 
 */
void mix_columns(uint8_t *block, size_t Nb)
{
  uint8_t  idx = 0;
  uint8_t  tmp[UAES_MAX_BLOCK_LEN] = {0};

  memcpy(tmp, block, 4*Nb);

  while(idx < Nb)
  {
    block[4*idx + 0] = gf256_mul(0x02, tmp[4*idx]) ^ gf256_mul(0x03, tmp[4*idx + 1]) ^ tmp[4*idx + 2] ^ tmp[4*idx + 3];
    block[4*idx + 1] = tmp[4*idx] ^ gf256_mul(0x02, tmp[4*idx + 1]) ^ gf256_mul(0x03, tmp[4*idx + 2]) ^ tmp[4*idx + 3];
    block[4*idx + 2] = tmp[4*idx] ^ tmp[4*idx + 1] ^ gf256_mul(0x02, tmp[4*idx + 2]) ^ gf256_mul(0x03, tmp[4*idx + 3]);
    block[4*idx + 3] = gf256_mul(0x03, tmp[4*idx]) ^ tmp[4*idx + 1] ^ tmp[4*idx + 2] ^ gf256_mul(0x02, tmp[4*idx + 3]); 
    idx++;
  }    
  return;
}

/**
 * @brief       Computes the inverse mix-columns operation on given data block.
 * @param block Pointer to the first element from the data block array.
 * @param Nb    Number of 32-bit words present on data block array. 
 */
void inv_mix_columns(uint8_t *block, size_t Nb)
{
  uint8_t idx = 0;
  uint8_t tmp[UAES_MAX_BLOCK_LEN] = {0};

  memcpy(tmp, block, 4*Nb);

  while( idx < Nb )
  {
    block[4*idx + 0] =  gf256_mul(0x0e, tmp[4*idx]) ^ gf256_mul(0x0b, tmp[4*idx + 1]) ^ gf256_mul(0x0d, tmp[4*idx + 2]) ^ gf256_mul(0x09, tmp[4*idx + 3]);
    block[4*idx + 1] =  gf256_mul(0x09, tmp[4*idx]) ^ gf256_mul(0x0e, tmp[4*idx + 1]) ^ gf256_mul(0x0b, tmp[4*idx + 2]) ^ gf256_mul(0x0d, tmp[4*idx + 3]);
    block[4*idx + 2] =  gf256_mul(0x0d, tmp[4*idx]) ^ gf256_mul(0x09, tmp[4*idx + 1]) ^ gf256_mul(0x0e, tmp[4*idx + 2]) ^ gf256_mul(0x0b, tmp[4*idx + 3]);
    block[4*idx + 3] =  gf256_mul(0x0b, tmp[4*idx]) ^ gf256_mul(0x0d, tmp[4*idx + 1]) ^ gf256_mul(0x09, tmp[4*idx + 2]) ^ gf256_mul(0x0e, tmp[4*idx + 3]);
    idx++;
  }    
  return;
}

/**
 * @brief           Computes the key expansion algorithm on given user key for the encryption/decryption process.
 * @param key       Pointer to the first element of the user key array.
 * @param keysched  Pointer to the first element of key schedule array.
 * @param Nk        Number of 32-bit words to be computed for the key schedule.
 * @param Ns        Number of rounds on key expansion algorithm.
 */
void key_expansion(uint8_t *key, uint32_t *keysched, size_t Nk, size_t Ns)
{
  uint32_t tmp = 0;
  size_t idx = 0;
  while( idx < Nk )
  {
    keysched[idx] = ( uint32_t )( key[4*idx] | key[4*idx + 1] << 8 | key[4*idx + 2] << 16 | key[4*idx + 3] << 24 );
    idx++;
  }
  UAES_TRACE(UAES_TRACE_MSK_KEXP, "Start of key expansion algorithm!");
  idx = Nk;
  while( idx < Ns )
  {
      tmp = keysched[idx - 1];
      UAES_TRACE(UAES_TRACE_MSK_KEXP, "keyexp.tmp = %.8x", tmp);
      if( ( idx % Nk == 0 ) )
      {
          tmp = rotword(tmp);
          UAES_TRACE(UAES_TRACE_MSK_KEXP, "keyexp.after rotword = %.8x", tmp);
          tmp = sub_word(tmp);
          UAES_TRACE(UAES_TRACE_MSK_KEXP, "keyexp.after sub-word = %.8x", tmp);
          tmp ^= rcon(idx/Nk);
          UAES_TRACE(UAES_TRACE_MSK_KEXP, "keyexp.after XOR with rcon = %.8x", tmp);
      }
      else if ( ( Nk > 6 ) && ( idx % Nk == 4 ) )
      {
          tmp = sub_word(tmp);
          UAES_TRACE(UAES_TRACE_MSK_KEXP, "keyexp.after sub-word = %.8x", tmp);
      }
      keysched[idx] = keysched[idx - Nk] ^ tmp;
      UAES_TRACE(UAES_TRACE_MSK_KEXP, "keyexp.kschd[%lu] = %.8x", idx, keysched[idx]);
      idx++;
  }
  UAES_TRACE(UAES_TRACE_MSK_KEXP, "End of key expansion!");
  return;
}

/**
 * @brief           Computes round key addition on given data block.
 * @param block     Pointer to the first element from the data block array.
 * @param keysched  Pointer to the first element from the key schedule array
 * @param round     Correspondent encryption/decryption round.
 * @param Nb        Number of 32-bit words present on data block array.
 */
void add_round_key(uint8_t *block, uint32_t *keysched, size_t round, size_t Nb)
{
  uint8_t keyidx = round * Nb;
  uint32_t tmp = 0;   
  for(size_t C = 0; C < Nb; C++)
  {
    tmp = (uint32_t)( block[4*C] | block[4*C + 1] << 8 | block[4*C + 2] << 16 | block[4*C + 3] << 24 );
    tmp ^= keysched[keyidx];
    for (size_t R = 0; R < Nb; R++)
    {
      block[4*C + R] = ( uint8_t )( tmp >> 8 * R );
    }
    keyidx++;
  }
  return;
}