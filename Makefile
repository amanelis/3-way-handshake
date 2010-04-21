all: mypar mylab

mypar: parse.c
	gcc -Wall -g parse.c -o oparse -ldnet -lpcap

mylab: parse_lab.c
	gcc -Wall -g parse_lab.c -o lparse -ldnet -lpcap

clean:
	rm lparse
	rm oparse
