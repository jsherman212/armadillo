#include "instruction.h"

struct instruction *instruction_new(unsigned int hex, unsigned long PC){
	struct instruction *i = malloc(sizeof(struct instruction));

	i->hex = hex;
	i->PC = PC;

	return i;
}

void instruction_free(struct instruction *i){
	free(i);
}
