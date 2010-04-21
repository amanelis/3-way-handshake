CC = gcc
CFLAGS = -Wall -g
LIBS = -ldnet -lpcap

all: mypar mylab

mypar: parse.c
	$(CC) $(CFLAGS) parse.c -o oparse $(LIBS)

mylab: parse_lab.c
	$(CC) $(CFLAGS) parse_lab.c -o lparse $(LIBS)

clean:
	rm ./lparse
	rm ./oparse
