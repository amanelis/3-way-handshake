#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct contents {
	char vicip[40];
	char vicmc[32];
	char vicpt[32];

	char attip[32];
	char attmc[32];
	char attpt[32];

	char repvicip[32];
	char repvicmc[32];
	
	char repattip[32];
	char repattmc[32];

	char interface[32];

	char timing[32];
};	

// Replace newline with null character
void rmnl(char *s) {
  while ( *s != '\n' && *s != '\0' )
    s++;
  *s = '\0';
}

struct contents *readcfg(char *filename) {
	FILE *input;
	struct contents *p;
	p = malloc(sizeof(struct contents));
	
	if((input = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERROR: fopen()\n");
		exit(-1);
	}
		fgets(p->vicip, 34, input);
		rmnl(p->vicip);
		/*
		fscanf(input, p->vicmc);
		fscanf(input, p->vicpt);
		
		fscanf(input, p->attip);
		fscanf(input, p->attmc);
		fscanf(input, p->attpt);

		fscanf(input, p->repvicip);
		fscanf(input, p->repvicmc);

		fscanf(input, p->repattip);
		fscanf(input, p->repattmc);

		fscanf(input, p->interface);

		fscanf(input, p->timing);
		*/
	return p;
}

int main(int argc, char *argv[]) {
	if(argc !=2){
		fprintf(stderr, "USAGE: ./executable <config file>\n");
		return(-1);
	}

	char *file;
	file = argv[1];

	struct contents *s;
	
	s = readcfg(file);
	
	printf("%s\n", s->vicip);
	

	return(0);
}
