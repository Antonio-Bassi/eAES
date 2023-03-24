/**
 * @file    umem.c
 * @author  Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief   Memory allocation management functions source code for uAES.
 * @version 0.0
 * @date    2023-02-03
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef UAES_USR_MEM_IMPL
/* your header file goes here! */
#else
#include <memory.h>
#endif /* UAES_USR_IMPL */

#include "umem.h"

void* uaes_prvMalloc(size_t size)
{
  void* ptr = NULL;
#ifdef UAES_USR_MEM_IMPL
/* place your malloc call here! */
#else 
  ptr = malloc(size);
#endif
  return ptr;
}

void uaes_prvFree(void* ptr)
{
#ifdef UAES_USR_MEM_IMPL
  /* place your free call here! */
#else 
  free(ptr);
#endif
  return;
}