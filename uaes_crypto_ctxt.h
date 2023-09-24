/**
 * @file      uaes_crypto_ctxt.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     uAES Cryptography Context references and definitions. 
 * @version   0.0
 * @date      2023-09-23 YYYY-MM-DD
 * @note      tab = 2 spaces!
 * 
 * Copyright (C) 2022, Antonio Vitor Grossi Bassi
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#ifndef __uAES_CRYPTO_CTXT_H
#define __uAES_CRYPTO_CTXT_H

#include <stdlib.h>
#include <stdint.h>
#include "uaes.h"

typedef enum uaes_err
{
  uAES_OK       =  0,
  uAES_KLEN     = -1,
  uAES_INVLEN   = -2,
  uAES_NULL     = -3,
  uAES_
}uaes_err_t;

typedef struct uaes_crypto_ctxt
{
  const size_t    dmem_length;
  uint8_t const*  dmem;
  uint8_t*        iv;
  const size_t    data_buffer_length;
  uint8_t*        data_buffer;
  aes_length_t    key_length;


}uaes_crypto_ctxt_t;

#endif /* __uAES_CRYPTO_CTXT_H */











