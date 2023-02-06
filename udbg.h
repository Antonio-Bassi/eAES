/**
 * @file      udbg.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     Tracing and debug macro definitions for uAES
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces! 
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
#define uAES_TRACE_MSK_EVERY  0x2F

#ifdef __UAES_DEBUG__
#define uAES_TRACE( msk, fmt, ... )do {                         \
  if( trace_msk & msk )                                         \
    printf("debug[%d]:" fmt "\n", debug_line, ##__VA_ARGS__ );  \
  debug_line++;                                                 \
} while(0)
#define uAES_TRACE_BLOCK( msk, fmt, block, ... ) do {           \
  if( trace_msk & msk )                                         \
  {                                                             \
    printf("debug[%d]:" fmt, debug_line, ##__VA_ARGS__);        \
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