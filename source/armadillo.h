#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include "adefs.h"

// XXX little endian
int ArmadilloDisassembleNew(unsigned int opcode, unsigned long PC,
        struct ad_insn **out);
// XXX call to free ad_insn returned from ArmadilloDisassembleNew
int ArmadilloDone(struct ad_insn **);

#endif
