#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <termios.h>

#include "uaes.h"
#include "udbg.h"
#include "nist_fips197_luts.h"
 
int main(int argc, char** argv)
{

  ukey_t key_type = uAES256;
  int argx = 0;
  int enc_type = 0;
  unsigned char input[65] = {0};
  unsigned char key[32] = {0};
  
  while( argc > argx )
  {
    if( ( 0 == strcmp(argv[argx],"-t") ) )
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
    
    else if( ( 0 == strcmp(argv[argx], "-f") ) )
    {
      argx++;

    }

  }


  
  return 0;
}
