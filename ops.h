/**
 * @file      uaes_ops.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     References for cipher operator functions.
 * @version   0.0
 * @date      2022-12-25
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces!
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