#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "bits.h"
#include "DataProcessingImmediate.h"

static const char *ARM64_GeneralRegisters[] = {
	"X0", "X1", "X2", "X3", "X4", "X5", "X6",
	"X7", "X8", "X9", "X10", "X11", "X12",
	"X13", "X14", "X15", "X16", "X17", "X18",
	"X19", "X20", "X21", "X22", "X23", "X24",
	"X25", "X26", "X27", "X28", "FP", "LR" };

// try and disassemble given bytes in little endian
// returns a string with the instruction
char *disassemble(unsigned int instruction);

#endif
