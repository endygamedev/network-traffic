SCANNER=ps-scanner
STATS=ps-stats
BASIC=basic

CC_FLAGS=-std=gnu99 -Wall -Werror -Wpedantic -Wextra -lpthread -lrt
CC=gcc

all: $(BASIC).c recipient
	$(CC) $(BASIC).c $(SCANNER).c -o $(SCANNER) $(CC_FLAGS)

recipient:
	$(CC) $(STATS).c -o $(STATS) $(CC_FLAGS)

clean:
	rm -f $(SCANNER)
	rm -f $(STATS)
