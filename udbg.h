/**
 * @file      udbg.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     Tracing and debug macro definitions for micro-AES
 * @version   0.1
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

#define UAES_TRACE_MSK_FWD    0x01
#define UAES_TRACE_MSK_INV    0x02
#define UAES_TRACE_MSK_KEXP   0x04
#define UAES_TRACE_MSK_INPUT  0x08
#define UAES_TRACE_MSK_TRACE  0x10
#define UAES_TRACE_MSK_EVERY  0x1F

#ifdef __UAES_DEBUG__
#define UAES_TRACE( msk, fmt, ... )do {          \
  if( trace_msk & msk )                          \
    printf("debug->" fmt "\n", ##__VA_ARGS__ );  \
} while(0)
#define UAES_TRACE_BLOCK( msk, fmt, block, ... ) do {\
  if( trace_msk & msk )                              \
  {                                                  \
    printf("debug->" fmt, ##__VA_ARGS__);            \
    for(size_t pos = 0; pos < 16; pos++)             \
      printf("%.2x", block[pos]);                    \
  }                                                  \
  printf("\n");                                      \
}while (0)                                                                    
#else
#define UAES_TRACE( msk, fmt, ... )do {} while (0)
#define UAES_TRACE_BLOCK( msk, fmt, block, ... )do {} while(0)
#endif /*__UAES_DEBUG__*/

#endif /*UDBG_H*/