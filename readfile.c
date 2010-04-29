#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct contents {
	char vicip[32];
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

void readFile(char *filename) {
	FILE *infile;

	if((infile = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERROR: fopen()\n");
		exit(-1);
	}

	while(feof(input) == 0){
		fscanf(input, contents->vicip);
		fscanf(input, contents->vipmc);
		fscanf(input, contents->vicpt);
		
		fscanf(input, contents->attip);
		fscanf(input, contents->attmc);
		fscanf(input, contents->attpt);

		fscanf(input, contents->repvicip);
		fscanf(input, contents->repvicmc);

		fscanf(input, contents->repattip);
		fscanf(input, contents->repattmc);

		fscanf(input, contents->interface);

		fscanf(input, contents->timing);
	}



}
