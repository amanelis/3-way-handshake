CC = gcc
CFLAGS = -Wall -g
LIBS = -ldnet -lpcap

all: mypar mylab myprox

mypar: parse.c
	$(CC) $(CFLAGS) parse.c -o oparse $(LIBS)

mylab: parse_lab.c
	$(CC) $(CFLAGS) parse_lab.c -o lparse $(LIBS)

myprox: parse_lab.c proxy.c
	$(CC) $(CFLAGS) parse_lab.c proxy.c -o pparse $(LIBS)

clean:
	rm -f *.o ./lparse ./oparse ./pparse
