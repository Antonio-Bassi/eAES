/**
 * @file      umem.h
 * @author    Antonio V. G. Bassi (antoniovitor.gb@gmail.com)
 * @brief     Memory allocation management header file for uAES 
 * @version   0.0
 * @date      2022-12-23 YYYY-MM-DD
 * @copyright Copyright (c) 2022
 * @note      tab = 2 spaces!
 * 
 */

#ifndef UMEM_H
#define UMEM_H

/**
 * @note  This part of the file is dedicated for memory alignment procedures.
 *        For specifying the memory allocator check the second note further below.
 * 
 * @brief The macros below are responsible for aligning the required memory size
 *        of *x* in accordance with the alignment boundary *a*. 
 */

#define uAES_ALIGN_BNDRY 4
#define uAES_ALIGN_MASK (uAES_ALIGN_BNDRY - 1)
#define uAES_GET_ALIGN_MASK(x, mask)   (((x) + (mask) ) & ~(mask))
#define uAES_ALIGN(x, a) uAES_GET_ALIGN_MASK(x, (typeof(x)(a)) - 1);

/**
 * @note  Instead of assuming which memory allocator is being used we 
 *        require that the system integrator defines a set of functions
 *        that are supposed to be called for memory allocation. 
 *        This allows for more flexibility but requires a bit more of 
 *        work. The source code for the functions referenced below should 
 *        be provided at umem.c file. If no memory allocator is defined the
 *        standard malloc will be used.
 *        uAES only makes use of malloc and free functions.
 * 
 */

extern void *prv_malloc(size_t size);
extern void prv_free(void* ptr) ;

#endif /* UMEM_H */