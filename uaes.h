/**
 * @file      uaes.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     micro-aes API references and global data-types. 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces! 
 */

#ifndef UAES_H
#define UAES_H

typedef enum key_length
{
  UAES128 = 0,  // 128 bit-sized password.
  UAES192 = 1,  // 192 bit-sized password.
  UAES256 = 2,  // 256 bit-sized password.
  UAESRNG = 3   // Range of length options
}key_length_t;

extern uint8_t uaes_set_trace_msk(uint8_t msk);
extern int uaes_encryption(uint8_t* in, uint8_t* out, uint8_t* key, key_length_t key_length);
extern int uaes_decryption(uint8_t* in, uint8_t* out, uint8_t* pwrd, key_length_t length);

#endif /*UAES_H*/