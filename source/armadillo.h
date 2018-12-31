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

// call this when your instruction is in little endian
char *ArmadilloDisassemble(unsigned int hex, unsigned long PC);

// call this when your instruction is in big endian
char *ArmadilloDisassembleB(unsigned int hex, unsigned long PC);

#endif
