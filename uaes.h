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
  uAESRGE = 3   // Range of length options
}ukey_t;

/* Debug */
extern uint8_t   uaes_set_trace_msk(uint8_t msk);

/* Encryption */
extern int uaes128enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size);
extern int uaes192enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size);
extern int uaes256enc(uint8_t *plaintext, uint8_t *key, size_t plaintext_size);
/* Decryption */
extern int uaes128dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size);
extern int uaes192dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size);
extern int uaes256dec(uint8_t *ciphertext, uint8_t *key, size_t ciphertext_size);

#endif /*UAES_H*/