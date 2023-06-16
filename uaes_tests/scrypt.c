/**
 * @file    scrypt.c
 * @author  Antonio Vitor Grossi Bassi
 * @brief   Source code for file encryption with AES cryptography
 * @version 0.1
 * @date 2023-06-16
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
#include "string.h"
#include "malloc.h"
#include "nist_fips197_luts.h"
#include "../uaes.h"
#include "cbmp/cbmp.h"

typedef enum
{
  uAES_ECB  = 0,
  uAES_CBC  = 1,
  uAES_PCBC = 2,
  uAES_CFB  = 3
}cipher_t;

#define MAX_KEYSIZE           (32UL)
#define MAX_FPATHSTR          (256UL)
#define LSB                   (0b00000001)
#define ARG_MSK_FILE          (LSB << 0UL)
#define ARG_MSK_KEY           (LSB << 1UL)
#define ARG_MSK_CRYPTOTYPE    (LSB << 2UL)
#define ARG_MSK_CIPHERTYPE    (LSB << 3UL)


static unsigned int __strnlen(char *ptr, unsigned int limit)
{
  unsigned int s = 0UL;
  if( NULL != ptr )
  {
    for(s = 0; ((s < limit)&&(0x00 != ptr[s])); s++);
  }
  return s;
}

static void printhex(uint8_t *str, size_t str_size)
{
  if(NULL != str)
  {
    for(size_t c = 0; c < str_size; c++)
    {
      printf("%02x ", str[c]);
    }
    printf("\n");
  }
  return;
}

static void yprintmat(uint8_t *buf, size_t buf_size)
{
  size_t n_blocks = (buf_size >> 4);
  size_t block_offset = 0;
  for(size_t b=0; b < n_blocks; b++)
  {
    printf("block %lu\n", b);
    printf("+-----------+\n");
    block_offset = 16*b;
    for(size_t row=0; row < 4UL; row++)
    {
      printf("|%02x %02x %02x %02x|", 
              buf[4*row + 0 + block_offset], 
              buf[4*row + 1 + block_offset], 
              buf[4*row + 2 + block_offset], 
              buf[4*row + 3 + block_offset]);
      printf("\n");
    }
    printf("+-----------+");
    printf("\n");
  }
  return;
}

static void xprintmat(uint8_t *buf, size_t buf_size)
{
  if(NULL != buf)
  {
    printf("\n");
    size_t n_blocks = (buf_size >> 4);
    size_t block_offset = 0;
    for(size_t b=0; b < n_blocks; b++)
    {
      printf("block %lu\t\t", b);
    }
    printf("\n");

    for(size_t b=0; b < n_blocks; b++)
    {
      printf("+-----------+\t");
    }
    printf("\n");

    for(size_t row=0; row < 4UL; row++)
    {
      for(size_t b=0; b < n_blocks; b++)
      {
        block_offset = 16*b;
        printf("|%02x %02x %02x %02x|\t", 
            buf[4*row + 0 + block_offset], 
            buf[4*row + 1 + block_offset], 
            buf[4*row + 2 + block_offset], 
            buf[4*row + 3 + block_offset]);
      }
      printf("\n");
    }

    for(size_t b=0; b < n_blocks; b++)
    {
      printf("+-----------+\t");
    }
    printf("\n");
  }
  return;
}

int main(int argc, char **argv)
{
  BMP* img = NULL;
  char path[MAX_FPATHSTR] = {0};
  crypto_t encryption_type = uAES128;
  cipher_t cipher_mode     = uAES_ECB;
  int err = 0;
  int arg = 0;
  uint32_t argmsk = 0;
  size_t  key_buf_size = 0;
  size_t  aligned_size = 0;
  size_t  padding_size = 0;
  size_t  img_buf_size = 0;
  uint8_t z1 = 0, z2 = 0;
  uint8_t key[MAX_KEYSIZE];
  uint8_t *crypbuf = NULL;

  if(1UL < argc)
  {
    while(argc > arg)
    {
      if(0 == strcmp(argv[arg], "-f"))
      {
        argmsk = ((argmsk & (~ARG_MSK_FILE)) | (ARG_MSK_FILE));
        arg++;
        strncpy(path, argv[arg], MAX_FPATHSTR);
      }
      else if(0 == strcmp(argv[arg], "-t"))
      {
        argmsk = ((argmsk & (~ARG_MSK_CRYPTOTYPE)) | (ARG_MSK_CRYPTOTYPE));
        arg++;
        if(0 == strcmp(argv[arg], "128"))
        {
          encryption_type = uAES128;
        }
        else if(0 == strcmp(argv[arg], "192"))
        {
          encryption_type = uAES192;
        }
        else if(0 == strcmp(argv[arg], "256"))
        {
          encryption_type = uAES256;
        }
        else
        {
          encryption_type = encryption_type;
        }
      }
      else if(0 == strcmp(argv[arg], "-k"))
      {
        argmsk = ((argmsk & (~ARG_MSK_KEY)) | (ARG_MSK_KEY));
        arg++;
        key_buf_size = __strnlen(argv[arg], MAX_KEYSIZE);
        memcpy((void *)key, (void *)argv[arg], key_buf_size);
      }
      else if(0 == strcmp(argv[arg], "-c"))
      {
         argmsk = ((argmsk & (~ARG_MSK_CIPHERTYPE)) | (ARG_MSK_CIPHERTYPE));
         arg++;
        if(0 == strcmp(argv[arg], "ECB"))
        {
          cipher_mode = uAES_ECB;
        }
        else if(0 == strcmp(argv[arg], "CBC"))
        {
          cipher_mode = uAES_CBC;
        }
      }
      arg++;
    }
  
    if( 0 != (key_buf_size & uAES_BYTE_ALIGN_MASK) )
    {
      aligned_size = (uAES128==encryption_type)?(16UL):((uAES192==encryption_type)?(24UL):((uAES256==encryption_type)?(32UL):(0UL)));
      padding_size = aligned_size - key_buf_size;
      for(size_t padpos = 0; padpos < padding_size; padpos++)
      {
        key[key_buf_size + padpos] = ~(key[padpos] + z1) + 1;
        z1 = key[padpos] + z2;
        z2 = key[padpos];
      }
      key_buf_size = aligned_size;
    }

    img = bopen(path);
    img_buf_size = img->file_byte_number - img->pixel_array_start;
    if( 0 != (img_buf_size & uAES_BLOCK_ALIGN_MASK) )
    {
      img_buf_size = uAES_ALIGN(img_buf_size, uAES_BLOCK_ALIGN);
    }
    crypbuf = calloc(1UL, img_buf_size);
    if( NULL != crypbuf )
    {
      memcpy((void *) crypbuf, (void *)(img->file_byte_contents + img->pixel_array_start), (img->file_byte_number - img->pixel_array_start));
      switch (encryption_type)
      {
        case uAES128:
        {
          switch (cipher_mode)
          {
            case uAES_ECB:
            {
              err = uaes_ecb_encryption(crypbuf, img_buf_size, key, encryption_type);
              break;
            }
            case uAES_CBC:
            {
              err = uaes_cbc_encryption(crypbuf, img_buf_size, key, input_aes128, encryption_type);
              break;
            }
          }
          break;
        }
        case uAES192:
        {
          switch(cipher_mode)
          {
            case uAES_ECB:
            {
              err = uaes_ecb_encryption(crypbuf, img_buf_size, key, encryption_type);
              break;
            }
            case uAES_CBC:
            {
              err = uaes_cbc_encryption(crypbuf, img_buf_size, key, input_aes192, encryption_type);
              break;
            }
          }
          break;
        }
        case uAES256:
        {
          switch(cipher_mode)
          {
            case uAES_ECB:
            {
              err = uaes_ecb_encryption(crypbuf, img_buf_size, key, encryption_type);
              break;
            }
            case uAES_CBC:
            {
              err = uaes_cbc_encryption(crypbuf, img_buf_size, key, input_aes256, encryption_type);
              break;
            }   
          }
          break;
        }
        default:
          break;
      }/*switch (encryption_type)*/
      memcpy((void *)(img->file_byte_contents + img->pixel_array_start), (void *) crypbuf,  (img->file_byte_number - img->pixel_array_start));
      bwrite(img, "res.bmp");
      bclose(img);
      free(crypbuf);
    }/*if( NULL != crypbuf )*/ 


  }/*if(1UL < argc)*/
  return err;
}