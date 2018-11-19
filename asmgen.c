#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv, const char **envp){
	int limit = 31;

	for(int i=0; i<limit; i++){
		for(int j=0; j<limit; j++){
			printf("__asm__(\"MOV X%d, X%d\");", i, j);
			if(j == 29)
				printf(" // MOV X%d, FP", i);
			if(j == 30)
				printf(" // MOV X%d, LR", i);

			printf("\n");
		}
	}

	for(int i=0; i<limit; i++)
		printf("__asm__(\"MOV X%d, SP\");\n", i);

	for(int i=0; i<limit; i++){
		for(int j=0; j<limit; j++){
			printf("__asm__(\"MOV W%d, W%d\");\n", i, j);
		}
		
	}

	for(int i=0; i<limit; i++)
		printf("__asm__(\"MOV W%d, WZR\");\n", i);

	return 0;
}
