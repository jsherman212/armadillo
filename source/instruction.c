#include <stdlib.h>

#include "instruction.h"

struct instruction *instruction_new(unsigned int opcode, unsigned long PC){
    struct instruction *i = malloc(sizeof(struct instruction));

    i->opcode = opcode;
    i->PC = PC;

    return i;
}

void instruction_free(struct instruction *i){
    free(i);
}
