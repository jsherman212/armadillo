#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bits.h"
#include "DataProcessingImmediate.h"
#include "BranchExcSys.h"
#include "instruction.h"

// try and disassemble given bytes in little endian
// returns a string with the instruction
char *ArmadilloDisassemble(struct instruction *instr);

#endif
