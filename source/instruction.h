#ifndef _INSTRUCTION_H_
#define _INSTRUCTION_H_

struct instruction {
	unsigned int opcode;
	unsigned long PC;
};

struct instruction *instruction_new(unsigned int, unsigned long);
void instruction_free(struct instruction *);

#endif
