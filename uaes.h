/**
 * @file      uaes.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     uAES API references and global data-types. 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @note      tab = 2 spaces! 
 *
 *  Copyright (C) 2022, Antonio Vitor Grossi Bassi
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef UAES_H
#define UAES_H

#include "udbg.h"

/**
 * @brief The macros below aid on aligning memory sizes in accordance with 
 *        AES encryption format.
 */
#define uAES_BLOCK_ALIGN        16UL
#define uAES_BLOCK_ALIGN_MASK   (0x0000000F)
#define uAES_BYTE_ALIGN         8UL
#define uAES_BYTE_ALIGN_MASK    (0x00000007)
#define uAES_GET_ALIGN_MASK(x, mask)   (((x) + (mask) ) & ~(mask))
#define uAES_ALIGN(x, a) uAES_GET_ALIGN_MASK(x, (typeof(x))(a) - 1)

#define KB  (1024UL)
#define MB  (KB*KB)
#define uAES_MAX_INPUT_SIZE   (64UL*MB)
#define uAES_MAX_KEY_SIZE     (32UL)
#define uAES_BLOCK_SIZE       (16UL)

typedef enum aes_length
{
  uAES128 = 0,  // 128 bit key length.
  uAES192 = 1,  // 192 bit key length.
  uAES256 = 2,  // 256 bit key length.
  uAESRGE = 3   // Range of length options
}aes_length_t;

/* Debug */
extern uint8_t   uaes_set_trace_msk(uint8_t msk);

/* Encryption API*/

/** 
 * NOTE: AES-ECB IS NO LONGER CONSIDERED SAFE, USE IT AT YOUR OWN RISK. 
 */
extern int uaes_ecb_encryption( uint8_t   *plaintext, 
                                size_t    plaintext_size, 
                                uint8_t   *key, 
                                aes_length_t  crypto_mode);
/* ******************************************************************** */

extern int uaes_cbc_encryption( uint8_t   *plaintext, 
                                size_t    plaintext_size, 
                                uint8_t   *key, 
                                uint8_t   *init_vec,
                                aes_length_t  aes_mode);

extern int uaes128enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size);
extern int uaes192enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size);
extern int uaes256enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size);

/* Decryption API*/

/** 
 * NOTE: AES-ECB IS NO LONGER CONSIDERED SAFE, USE IT AT YOUR OWN RISK. 
 */
extern int uaes_ecb_decryption( uint8_t   *ciphertext, 
                                size_t    ciphertext_size, 
                                uint8_t   *key, 
                                aes_length_t  crypto_mode );
/* ******************************************************************** */

extern int uaes_cbc_decryption( uint8_t   *plaintext, 
                                size_t    plaintext_size, 
                                uint8_t   *key, 
                                uint8_t   *init_vec,
                                aes_length_t  aes_mode );


extern int uaes128dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size);
extern int uaes192dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size);
extern int uaes256dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size);

#endif /*UAES_H*/
