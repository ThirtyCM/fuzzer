CC = gcc
CFLAGS = -Wall -Werror

fuzzer : fuzzer.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY : clean

clean :
	rm -f fuzzer
	rm -f *.tar