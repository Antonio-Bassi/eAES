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

typedef struct header
{             
  uint32_t  id;                       
  uint32_t  size;                     
  uint32_t  rsvd;                     
  uint32_t  offset;                   
  uint32_t  dib_header_size;          
  uint32_t  width_px;                 
  uint32_t  height_px;                
  uint16_t  num_planes;               
  uint16_t  bits_per_pixel;           
  uint32_t  compression;              
  uint32_t  image_size_bytes;         
  uint32_t   x_resolution_ppm;        
  uint32_t   y_resolution_ppm;        
  uint32_t  num_colors;               
  uint32_t  important_colors;         
  uint32_t  red_ch_bitmask;           
  uint32_t  green_ch_bitmask;         
  uint32_t  blue_ch_bitmask;          
  uint32_t  alpha_ch_bitmask;         
  uint32_t  color_space_type;         
  uint32_t  color_space_endpts[9UL];  
  uint32_t  red_gamma_lvl;            
  uint32_t  green_gamma_lvl;          
  uint32_t  blue_gamma_lvl;           
  uint32_t  intent;
  uint32_t  icc_profile_data;
  uint32_t  icc_profile_size;
  uint32_t  reserved3;  
}header_t;

typedef struct bmp
{
  header_t header;  // file header
  uint8_t  *px;     // Pixel array
}bmp_t;

int bmp_little2big(uint32_t *ptr, size_t length)
{
  int err = -1;
  uint32_t b0, b1, b2, b3;
  if((NULL != ptr)&&(0 < length))
  {
    for(size_t w = 0; w < length; w++)
    {
      b0 = ((ptr[w] & 0x000000FF) << 24UL);
      b1 = ((ptr[w] & 0x0000FF00) << 8UL );
      b2 = ((ptr[w] & 0x00FF0000) >> 8UL);
      b3 = ((ptr[w] & 0xFF000000) >> 24UL);

      ptr[w] = (b0 | b1 | b2 | b3);
    }
    err = 0;
  }
  return err;
}


int main(int argc, char **argv)
{
  char path[MAX_FPATHSTR] = {0};
  crypto_t encryption_type = uAES128;
  cipher_t cipher_mode     = uAES_ECB;
  int err = 0;
  int arg = 0;
  uint32_t argmsk         = 0;
  size_t  key_buf_size    = 0;
  size_t  aligned_size    = 0;
  size_t  padding_size    = 0;
  size_t  img_px_size     = 0;
  size_t  aligned_px_size = 0;
  size_t  i = 0;
  uint8_t z1 = 0, z2 = 0;
  uint8_t key[MAX_KEYSIZE];

  FILE *fstream = NULL;
  bmp_t *img    = NULL; 

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

    fstream = fopen(path, "rb+");
    if(NULL != fstream)
    {
      img = (bmp_t *)malloc(sizeof(bmp_t));
      if(NULL != img)
      {
        fseek(fstream, 0UL, SEEK_SET);
        fread((void *)&img->header, 4UL, 28UL, fstream);
        bmp_little2big((uint32_t *)&img->header, 28UL);
        img_px_size = (size_t)(img->header.width_px * img->header.height_px);
        aligned_px_size = uAES_ALIGN(img_px_size, uAES_BLOCK_ALIGN);
        img->px = (uint8_t *)calloc(1UL, aligned_px_size);
        if(NULL != img->px)
        {
          fseek(fstream, img->header.offset, SEEK_SET);
          while( (EOF != fscanf(fstream, "%c", &img->px[i])) && (i < aligned_px_size))
          {
            i++;
          }
          aligned_px_size = uAES_ALIGN(i, uAES_BLOCK_ALIGN);
          img->px =(uint8_t *) realloc((void *)img->px, aligned_px_size);
        }
      }
    }

    if( NULL != img->px )
    {
      switch (encryption_type)
      {
        case uAES128:
        {
          switch (cipher_mode)
          {
            case uAES_ECB:
            {
              err = uaes_ecb_encryption(img->px, aligned_px_size, key, encryption_type);
              break;
            }
            case uAES_CBC:
            {
              err = uaes_cbc_encryption(img->px, aligned_px_size, key, input_aes128, encryption_type);
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
              err = uaes_ecb_encryption(img->px, aligned_px_size, key, encryption_type);
              break;
            }
            case uAES_CBC:
            {
              err = uaes_cbc_encryption(img->px, aligned_px_size, key, input_aes192, encryption_type);
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
              err = uaes_ecb_encryption(img->px, aligned_px_size, key, encryption_type);
              break;
            }
            case uAES_CBC:
            {
              err = uaes_cbc_encryption(img->px, aligned_px_size, key, input_aes256, encryption_type);
              break;
            }   
          }
          break;
        }
        default:
          break;
      }/*switch (encryption_type)*/
      fwrite(img->px, 1UL, aligned_px_size, fstream);
      free(img->px);
    }/*if( NULL != img->px )*/ 
    fclose(fstream);
    free(img);
  }/*if(1UL < argc)*/
  return err;
}