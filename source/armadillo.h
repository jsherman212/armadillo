#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bits.h"
#include "instruction.h"

#include "BranchExcSys.h"
#include "DataProcessingImmediate.h"
#include "DataProcessingFloatingPoint.h"
#include "DataProcessingRegister.h"
#include "LoadsAndStores.h"

// client calls this
char *ArmadilloDisassemble(unsigned int hex, unsigned long PC);

// try and disassemble given bytes in little endian
// returns a string with the instruction
char *_ArmadilloDisassemble(struct instruction *instr);

#endif
