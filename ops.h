/**
 * @file      uaes_ops.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     References for cipher operator functions.
 * @version   0.0
 * @date      2022-12-25
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
 *
 */

#ifndef OPS_H
#define OPS_H

extern void sub_block(uint8_t* block, size_t Nb);
extern void inv_sub_block(uint8_t* block, size_t Nb);
extern void shift_rows(uint8_t* block, size_t Nb);
extern void inv_shift_rows(uint8_t* block, size_t Nb);
extern void mix_columns(uint8_t* block, size_t Nb);
extern void inv_mix_columns(uint8_t* block, size_t Nb);
extern void key_expansion(uint8_t* key, uint32_t* keysched, size_t Nk, size_t Ns);
extern void add_round_key(uint8_t* block, uint32_t* keysched, size_t round, size_t Nb);

#endif /*OPS_H*/
