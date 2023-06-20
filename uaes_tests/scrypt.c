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
#include "cbmp/cbmp.h"
#include "../uaes.h"

typedef enum
{
  uAES_ECB  = 0,
  uAES_CBC  = 1,
  uAES_PCBC = 2,
  uAES_CFB  = 3
}cipher_t;

typedef enum
{
  uAES_ENCRYPT,
  uAES_DECRYPT
}uaes_mode_t;

#define MAX_KEYSIZE           (32UL)
#define MAX_FPATHSTR          (128UL)
#define LSB                   (0b00000001)
#define ARG_MSK_FILE          (LSB << 0UL)
#define ARG_MSK_KEY           (LSB << 1UL)
#define ARG_MSK_CRYPTOTYPE    (LSB << 2UL)
#define ARG_MSK_CIPHERTYPE    (LSB << 3UL)
#define ARG_MSK_OUTFNAME      (LSB << 4UL)
#define ARG_MSK_MODE          (LSB << 5UL)

static unsigned int __strnlen(char *ptr, unsigned int limit)
{
  unsigned int s = 0UL;
  if( NULL != ptr )
  {
    for(s = 0; ((s < limit)&&(0x00 != ptr[s])); s++);
  }
  return s;
}

int rd_argmsk(uint32_t *argmsk, uint32_t msk)
{
  return (*argmsk & msk) ? (0UL) : (1UL);
}

int main(int argc, char **argv)
{
  char path[MAX_FPATHSTR] = {0};
  char outf[MAX_FPATHSTR] = {0};
  uaes_mode_t operation_mode  = uAES_ENCRYPT;
  crypto_t encryption_type = uAES128;
  cipher_t cipher_mode     = uAES_ECB;
  int err = 0;
  int arg = 0;
  uint32_t argmsk         = 0;
  size_t  key_buf_size    = 0;
  size_t  aligned_size    = 0;
  size_t  padding_size    = 0;
  size_t  pxLayer_size    = 0;
  size_t  i = 0;
  uint8_t z1 = 0, z2 = 0;
  size_t  w = 0, h = 0;
  uint8_t *iv = NULL;
  uint8_t *r = NULL, *g = NULL, *b = NULL;
  uint8_t key[MAX_KEYSIZE];
  BMP *img    = NULL; 

  if(1UL < argc)
  {
    while(argc > arg)
    {
      if((0 == strcmp(argv[arg], "-f")) && (rd_argmsk(&argmsk, ARG_MSK_FILE)))
      {
        argmsk = ((argmsk & (~ARG_MSK_FILE)) | (ARG_MSK_FILE));
        arg++;
        strncpy(path, argv[arg], MAX_FPATHSTR);
      }
      else if((0 == strcmp(argv[arg], "-o")) && (rd_argmsk(&argmsk, ARG_MSK_OUTFNAME)))
      {
        argmsk = ((argmsk & (~ARG_MSK_OUTFNAME)) | (ARG_MSK_OUTFNAME));
        arg++;
        strncpy(outf, argv[arg], MAX_FPATHSTR);
      }
      else if((0 == strcmp(argv[arg], "-t")) && (rd_argmsk(&argmsk, ARG_MSK_CRYPTOTYPE)))
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
      else if((0 == strcmp(argv[arg], "-k")) && (rd_argmsk(&argmsk, ARG_MSK_KEY)))
      {
        argmsk = ((argmsk & (~ARG_MSK_KEY)) | (ARG_MSK_KEY));
        arg++;
        key_buf_size = __strnlen(argv[arg], MAX_KEYSIZE);
        memcpy((void *)key, (void *)argv[arg], key_buf_size);
      }
      else if((0 == strcmp(argv[arg], "-c")) && (rd_argmsk(&argmsk, ARG_MSK_CIPHERTYPE)))
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
      else if((0 == strcmp(argv[arg], "-d"))  && (rd_argmsk(&argmsk, ARG_MSK_MODE)))
      {
        argmsk = ((argmsk & (~ARG_MSK_MODE)) | (ARG_MSK_MODE));
        operation_mode = uAES_DECRYPT;
      }
      else if(0 == strcmp(argv[arg], "-h"))
      {
        printf("scrypt: Test script for uAES API, applies AES encryption on bitmap image files.\n");
        printf("usage: scrypt -f [FILENAME] -o [OUTPUT FILE] [PARAMETERS]\n");
        printf("Takes following arguments:\n\"-f\", file name with extension.\n\"-o\", output file name with extension.\n");
        printf("\"-k\", AES key value, if lenght is less than the specified in argument \"-t\" padding is applied.\n");
        printf("\"-t\", Cryptography mode, can be 128, 192 or 256.\n");
        printf("\"-c\", Cipher mode, can be EBC or CBC.\n");
        printf("\"-d\", Specifies decryption operation. If nothing is specified, encryption is performed.\n");
        printf("example: scrypt -f \"yourpic.bmp\" -o \"res.bmp\" -k \"youarebeautiful!\" -t 128 -c ECB\n\n");
        exit(EXIT_SUCCESS);
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
    if(NULL != img)
    {
      w = img->width;
      h = img->height;
      pxLayer_size = uAES_ALIGN((w*h), uAES_BLOCK_ALIGN);
      r = (uint8_t *)calloc(1UL, pxLayer_size);
      g = (uint8_t *)calloc(1UL, pxLayer_size);
      b = (uint8_t *)calloc(1UL, pxLayer_size);

      for(int x = 0; x < w; x++)
      {
        for(int y = 0; y < h; y++)
        {
          get_pixel_rgb(img, x, y, &r[(y*img->width) + x], &g[(y*img->width) + x], &b[(y*img->width) + x]);
        }
      }
    }

    if( (NULL != r) && (NULL != g) && (NULL != b) )
    {
      switch (cipher_mode)
      {
        case uAES_ECB:
        {
          if(uAES_ENCRYPT == operation_mode)
          {
            err = uaes_ecb_encryption(r, pxLayer_size, key, encryption_type);
            err = uaes_ecb_encryption(g, pxLayer_size, key, encryption_type);
            err = uaes_ecb_encryption(b, pxLayer_size, key, encryption_type);
          }
          else if(uAES_DECRYPT == operation_mode)
          {
            err = uaes_ecb_decryption(r, pxLayer_size, key, encryption_type);
            err = uaes_ecb_decryption(g, pxLayer_size, key, encryption_type);
            err = uaes_ecb_decryption(b, pxLayer_size, key, encryption_type);
          }
          for(int x = 0; x < w; x++)
          {
            for(int y = 0; y < h; y++)
            {
              set_pixel_rgb(img, x, y, r[(y*img->width) + x], g[(y*img->width) + x], b[(y*img->width) + x]);
            }
          } 
          break;
        }
        case uAES_CBC:
        {
          switch(encryption_type)
          {
            case uAES128:
              iv = input_aes128;
              break;
            case uAES192:
              iv = input_aes192;
              break;
            case uAES256:
              iv = input_aes256;
              break;
          }
          if( uAES_ENCRYPT == operation_mode )
          {
            err = uaes_cbc_encryption(r, pxLayer_size, key, iv, encryption_type);
            err = uaes_cbc_encryption(g, pxLayer_size, key, iv, encryption_type);
            err = uaes_cbc_encryption(b, pxLayer_size, key, iv, encryption_type);
          }
          else if(uAES_DECRYPT == operation_mode)
          { 
            err = uaes_cbc_decryption(r, pxLayer_size, key, iv, encryption_type);
            err = uaes_cbc_decryption(g, pxLayer_size, key, iv, encryption_type);
            err = uaes_cbc_decryption(b, pxLayer_size, key, iv, encryption_type);
          }
          for(int x = 0; x < w; x++)
          {
            for(int y = 0; y < h; y++)
            {
              set_pixel_rgb(img, x, y, r[(y*img->width) + x], g[(y*img->width) + x], b[(y*img->width) + x]);
            }
          }
          break;
        }
      }
      bwrite(img, outf);
      bclose(img);
      free(r);
      free(g);
      free(b);
    }
  }/*if(1UL < argc)*/
  return err;
}