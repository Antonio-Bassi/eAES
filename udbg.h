/**
 * @file      udbg.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     Tracing and debug macro definitions for uAES
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @note      tab = 2 spaces! 
 *
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

#ifndef UDBG_H
#define UDBG_H

/* 
 * trace macro options:
 *            +----+----+----+----+----+----+----+----+
 * trace_msk= | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
 *            +----+----+----+----+----+----+----+----+
 * b7 - Reserved for future use. Will be ignored.
 * b6 - Reserved for future use. Will be ignored.
 * b5 - Reserved for future use. Will be ignored.
 * b4 - Informs if tracing is enabled and traces arguments and errors.
 * b3 - Displays information about the given input.
 * b2 - Traces key expansion algorithm.
 * b1 - Traces inverse cipher algorithm.
 * b0 - Traces foward cipher algorithm.
 * 
 */

extern uint8_t trace_msk;
extern int debug_line;

#define uAES_TRACE_MSK_FWD    0x01
#define uAES_TRACE_MSK_INV    0x02
#define uAES_TRACE_MSK_KEXP   0x04
#define uAES_TRACE_MSK_INPUT  0x08
#define uAES_TRACE_MSK_TRACE  0x10
#define uAES_TRACE_MSK_MEM    0x20
#define uAES_TRACE_MSK_EVERY  0x3F

#ifdef __uAES_DEBUG__
#define uAES_TRACE( msk, fmt, ... )do {                         \
  if( trace_msk & msk )                                         \
    printf("dbg[%d]:" fmt "\n", debug_line, ##__VA_ARGS__ );  \
  debug_line++;                                                 \
} while(0)
#define uAES_TRACE_BLOCK( msk, fmt, block, ... ) do {           \
  if( trace_msk & msk )                                         \
  {                                                             \
    printf("dbg[%d]:" fmt, debug_line, ##__VA_ARGS__);        \
    for(size_t pos = 0; pos < 16; pos++)                        \
      printf("%.2x", block[pos]);                               \
  }                                                             \
  debug_line++;                                                 \
  printf("\n");                                                 \
}while (0)                                                                    
#else
#define uAES_TRACE( msk, fmt, ... )do {} while (0)
#define uAES_TRACE_BLOCK( msk, fmt, block, ... )do {} while(0)
#endif /*__UAES_DEBUG__*/

#endif /*UDBG_H*/
