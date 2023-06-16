#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <termios.h>

#include "../uaes.h"
#include "nist_fips197_luts.h"

#define MAX_DIRSTR    255UL
#define MAX_INPUTSTR  64UL
#define MAX_KEYSTR    32UL

static inline void enable_shell_echo(void);
static inline void disable_shell_echo(void); 
static void xprintmat(uint8_t *buf, size_t buf_size);
static void yprintmat(uint8_t *buf, size_t buf_size);
static void printhex(uint8_t *str, size_t str_size);

static inline void enable_shell_echo(void)
{
  struct termios shell;
  tcgetattr(fileno(stdin), &shell);
  shell.c_lflag |= ECHO;
  tcsetattr(fileno(stdin), 0, &shell);
  return;
}

static inline void disable_shell_echo(void)
{
  struct termios shell;
  tcgetattr(fileno(stdin), &shell);
  shell.c_lflag &= ~ECHO;
  tcsetattr(fileno(stdin), 0, &shell);
  return;
}

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

#define LSB                 (0b00000001)
#define ARG_MSK_PLAINTEXT   (LSB << 0UL)
#define ARG_MSK_KEY         (LSB << 1UL)
#define ARG_MSK_CRYPTOTYPE  (LSB << 2UL)
#define ARG_MSK_CIPHERTYPE  (LSB << 3UL)

typedef enum
{
  uAES_ECB  = 0,
  uAES_CBC  = 1,
  uAES_PCBC = 2,
  uAES_CFB  = 3
}cipher_t;

int main(int argc, char **argv)
{
  const int min_args = 3;
  int     arg =  1;
  int     err = -1;
  uint8_t   argmsk = 0x00;
  cipher_t  cipher_mode = uAES_ECB;
  crypto_t  encryption_type = uAES128;
  size_t    aligned_size = 0;
  size_t    padding_size = 0;
  size_t    input_size = 0;
  size_t    key_buffer_size = 0;
  uint8_t   checksum = 0;
  uint8_t   z1 = 0, z2 = 0;
  uint8_t   key[MAX_KEYSTR] = {0};
  uint8_t   in[MAX_INPUTSTR] = {0};
  uint8_t   *out = NULL;

  uaes_set_trace_msk((uAES_TRACE_MSK_FWD | uAES_TRACE_MSK_INV | uAES_TRACE_MSK_KEXP));

  if(min_args <= argc)
  {
    while(arg < argc)
    {
      if((0 == strcmp(argv[arg],"-k")) && (0 == (argmsk & ARG_MSK_KEY)))
      {
        argmsk = ((argmsk & (~ARG_MSK_KEY)) | (ARG_MSK_KEY));
        arg++;
        key_buffer_size = __strnlen(argv[arg], MAX_KEYSTR);
        memcpy((void *)key, (void *)argv[arg], key_buffer_size);
      }
      else if((0 == strcmp(argv[arg], "-p")) && (0 == (argmsk & ARG_MSK_PLAINTEXT)))
      {
        argmsk = ((argmsk & (~ARG_MSK_PLAINTEXT)) | (ARG_MSK_PLAINTEXT));
        arg++;
        input_size = __strnlen(argv[arg], MAX_INPUTSTR);
        memcpy((void *)in, (void *)argv[arg], input_size);
      }
      else if((0 == strcmp(argv[arg], "-t")) && (0 == (argmsk & ARG_MSK_CRYPTOTYPE)))
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
      else if((0 == strcmp(argv[arg], "-c")) && (0 == (argmsk & ARG_MSK_CIPHERTYPE)))
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
        else if(0 == strcmp(argv[arg], "PCBC"))
        {
          // TODO: Yet to implement, ignore for now.
        }
        else if(0 == strcmp(argv[arg], "CFB"))
        {
          // TODO: Yet to implement, ignore fow now.
        }  
        else
        {
          cipher_mode = uAES_ECB;
        }
      }
      arg++;
    }

    if( 0 != (key_buffer_size & uAES_BYTE_ALIGN_MASK) )
    {
      aligned_size = (uAES128==encryption_type)?(16UL):((uAES192==encryption_type)?(24UL):((uAES256==encryption_type)?(32UL):(0UL)));
      padding_size = aligned_size - key_buffer_size;
      for(size_t padpos = 0; padpos < padding_size; padpos++)
      {
        key[key_buffer_size + padpos] = ~(key[padpos] + z1) + 1;
        z1 = key[padpos] + z2;
        z2 = key[padpos];
      }
      key_buffer_size = aligned_size;
    }
    if( 0 != (input_size & uAES_BLOCK_ALIGN_MASK) )
    {
      input_size = uAES_ALIGN(input_size, uAES_BLOCK_ALIGN);
    }

    printf("Received input: ");
    printhex(in, input_size);
    printf("Received key: ");
    printhex(key, key_buffer_size);
    printf("Total plaintext blocks: ");
    xprintmat(in, input_size);
    
    switch (encryption_type)
    {
      case uAES128:
      {
        switch (cipher_mode)
        {
          case uAES_ECB:
          {
            err = uaes_ecb_encryption(in, input_size, key, encryption_type);
            printf("AES128-ECB Encrypted plaintext blocks: ");
            xprintmat(in, input_size);
            err = uaes_ecb_decryption(in, input_size, key, encryption_type);
            printf("AES128-ECB Decrypted plaintext blocks: ");
            xprintmat(in, input_size);
            break;
          }
          case uAES_CBC:
          {
            err = uaes_cbc_encryption(in, input_size, key, input_aes128, encryption_type);
            printf("AES128-CBC Encrypted plaintext blocks: ");
            xprintmat(in, input_size);
            err = uaes_cbc_decryption(in, input_size, key, input_aes128, encryption_type);
            printf("AES128-CBC Decrypted plaintext blocks: ");
            xprintmat(in, input_size);
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
            err = uaes_ecb_encryption(in, input_size, key, encryption_type);
            printf("AES192-ECB Encrypted plaintext blocks: ");
            xprintmat(in, input_size);
            err = uaes_ecb_decryption(in, input_size, key, encryption_type);
            printf("AES192-ECB Decrypted plaintext blocks: ");
            xprintmat(in, input_size);
            break;
          }
          case uAES_CBC:
          {
            err = uaes_cbc_encryption(in, input_size, key, input_aes192, encryption_type);
            printf("AES192-CBC Encrypted plaintext blocks: ");
            xprintmat(in, input_size);
            err = uaes_cbc_decryption(in, input_size, key, input_aes192, encryption_type);
            printf("AES192-CBC Decrypted plaintext blocks: ");
            xprintmat(in, input_size);
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
            err = uaes_ecb_encryption(in, input_size, key, encryption_type);
            printf("AES256-ECB Encrypted plaintext blocks: ");
            xprintmat(in, input_size);
            err = uaes_ecb_decryption(in, input_size, key, encryption_type);
            printf("AES256-ECB Decrypted plaintext blocks: ");
            xprintmat(in, input_size);
            break;
          }
          case uAES_CBC:
          {
            err = uaes_cbc_encryption(in, input_size, key, input_aes256, encryption_type);
            printf("AES256-CBC Encrypted plaintext blocks: ");
            xprintmat(in, input_size);
            err = uaes_cbc_decryption(in, input_size, key, input_aes256, encryption_type);
            printf("AES256-CBC Decrypted plaintext blocks: ");
            xprintmat(in, input_size);
            break;
          }   
        }
        break;
      }
      default:
        break;
    }
  }
  return err;
}