#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <termios.h>

#include "uaes.h"
#include "udbg.h"
#include "nist_fips197_luts.h"

#define MAX_DIRSTR  255
#define MAX_INSTR   64
#define MAX_KEYSTR  32

static inline void enable_shell_echo(void);
static inline void disable_shell_echo(void);
static void printmat(uint8_t *buf);

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

static void printmat(uint8_t *buf)
{

  return;
}

int main(int argc, char **argv)
{
  ukey_t key_type = uAES256;
  int argx = 0;
  int enc_type = 0;
  int idx = 0;
  char *cipher = NULL;
  char path [MAX_DIRSTR + 1] = {0};
  char input[MAX_INSTR + 1] = {0};
  char key  [MAX_KEYSTR + 1] = {0};

  while( argc > argx )
  {
    if( ( 0 == strcmp(argv[argx],"-b") ) )
    {
      argx++;
      enc_type = atoi(argv[argx]);
      switch(enc_type)
      {
        case 128:
          key_type = uAES128;
          break;
        case 192:
          key_type = uAES192;
          break;
        case 256:
          key_type = uAES256;
          break;
        default:
          break;
      }
    }

    // If no options are set, get input text.
    else
    {
      strncpy(input, &argv[argx], MAX_INSTR);
    }
  }

  disable_shell_echo();
  printf("Type in key for AES%d encryption:", enc_type);
  scanf("%s", key);
  enable_shell_echo();

  cipher = uaes_encryption(input, key, key_type);

  return 0;
}
