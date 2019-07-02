#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

// call this when your instruction is in little endian
char *ArmadilloDisassemble(unsigned int opcode, unsigned long PC);

// call this when your instruction is in big endian
char *ArmadilloDisassembleB(unsigned int opcode, unsigned long PC);

#endif
