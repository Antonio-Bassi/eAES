/**
 * @file      uaes.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     uAES API references and global data-types. 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces! 
 */

#ifndef UAES_H
#define UAES_H

#define UAES_MAX_LBL_LEN 10

typedef enum ukey
{
  uAES128 = 0,  // 128 bit-sized password.
  uAES192 = 1,  // 192 bit-sized password.
  uAES256 = 2,  // 256 bit-sized password.
  uAESRNG = 3   // Range of length options
}ukey_t;

extern uint8_t   uaes_set_trace_msk(uint8_t msk);
extern uint8_t*  uaes_encryption(uint8_t* in, uint8_t* key, ukey_t key_type);
extern void      uaes_decryption(uint8_t* in, uint8_t* key, uint8_t *out);

#endif /*UAES_H*/