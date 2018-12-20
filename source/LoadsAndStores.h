#ifndef _LOADSANDSTORES_H_
#define _LOADSANDSTORES_H_

#include "common.h"
#include "instruction.h"
#include "utils.h"

#define NO_ALLOCATE 0
#define POST_INDEXED 1
#define OFFSET 2
#define PRE_INDEXED 3

char *LoadsAndStoresDisassemble(struct instruction *instruction);

#endif
