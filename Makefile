CC = gcc
CFLAGS = -Wall -g
LIBS = -ldnet -lpcap

all: mylab myprox

mypar: parse.c
	$(CC) $(CFLAGS) parse.c -o oparse $(LIBS)

mylab: parse_lab.c
	$(CC) $(CFLAGS) parse_lab.c -o lparse $(LIBS)

myprox: proxy.c parse_lab.c
	$(CC) $(CFLAGS) proxy.c parse_lab.c -o pparse $(LIBS)

proxy: proxy.c
	$(CC) $(CFLAGS) proxy.c -o proxy $(LIBS)

clean:
	rm -f *.o ./oparse ./lparse ./pparse ./proxy
