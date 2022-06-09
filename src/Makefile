MAIN=main
RECIP=recipient
BASIC=basic
LOG=log

CC_FLAGS=-std=gnu99 -Wall -Werror -Wpedantic -Wextra -lpthread -lrt
CC=gcc

all: $(BASIC).c recipient
	$(CC) $(BASIC).c $(MAIN).c -o $(MAIN) $(CC_FLAGS)

recipient:
	$(CC) $(RECIP).c -o $(RECIP) $(CC_FLAGS)

clean:
	rm -f $(MAIN)
	rm -f $(LOG)
	rm -f $(RECIP)
