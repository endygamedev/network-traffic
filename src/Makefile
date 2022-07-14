SCANNER1=ps-scanner-1
SCANNER2=ps-scanner-2
STATS=ps-stats
BASIC=basic

CC_FLAGS=-std=gnu99 -Wall -Werror -Wpedantic -Wextra -lpthread -lrt
CC=gcc

all: scanner stats

scanner: $(BASIC).c stats
	$(CC) $(BASIC).c $(SCANNER1).c -o $(SCANNER1) $(CC_FLAGS)
	$(CC) $(BASIC).c $(SCANNER2).c -o $(SCANNER2) $(CC_FLAGS)


stats:
	$(CC) $(STATS).c -o $(STATS) $(CC_FLAGS)

clean:
	rm -f $(SCANNER1)
	rm -f $(SCANNER2)
	rm -f $(STATS)
