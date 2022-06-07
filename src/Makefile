MAIN=main
BASIC=basic
LOG=log
CC_FLAGS=-std=gnu99 -Wall -Werror -Wpedantic -Wextra
CC=gcc

all: $(BASIC).c
	$(CC) $(CC_FLAGS) $(BASIC).c $(MAIN).c -o $(MAIN)

clean:
	rm -f $(MAIN)
	rm -f $(LOG)
