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

