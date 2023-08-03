.PHONY: test clean

OUT_NAME = scrypt

INC = \
	-I uaes_tests/cbmp \
	-I uaes_tests			 \

SRC_CBMP = \
	$(wildcard ./uaes_tests/cbmp/*.c)
  
SRC_UAES = \
	$(wildcard ./*.c)

TARGET_SRC = \
	./uaes_tests/scrypt.c

clean:
	@rm -f $(OUT_NAME) 

test:
	@gcc $(TARGET_SRC) $(SRC_UAES) $(SRC_CBMP) -o $(OUT_NAME) $(INC)
