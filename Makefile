.PHONY: test clean

OUT_NAME = scrypt

INC_GCC = \
	-I uaes_tests/cbmp \
	-I uaes_tests			 \

INC_ARM = \
# Add include paths for compiling process with arm-none-eabi-gcc

SRC_CBMP = \
	$(wildcard ./uaes_tests/cbmp/*.c)
  
SRC_UAES = \
	$(wildcard ./*.c)

TARGET_SRC_GCC = \
	./uaes_tests/scrypt.c

TARGET_SRC_ARM = \
# Add source paths for compiling process with arm-none-eabi-gcc

clean:
	@rm -f $(OUT_NAME) 

test:
	@gcc $(TARGET_SRC_GCC) $(SRC_UAES) $(SRC_CBMP) $(INC_GCC) -o $(OUT_NAME)

arm32bit: 
	@arm-none-eabi-gcc $(TARGET_SRC_GCC) $(SRC_UAES) $(INC_ARM) -o $(OUT_NAME)
