#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include "adefs.h"

int ArmadilloDisassemble(unsigned int opcode, unsigned long PC, struct ad_insn **out);
int ArmadilloDone(struct ad_insn **insn);

#endif
