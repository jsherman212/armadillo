#ifndef _DATAPROCESSINGREGISTER_H_
#define _DATAPROCESSINGREGISTER_H_

#include "common.h"
#include "instruction.h"
#include "utils.h"

#define SHIFTED 0
#define EXTENDED 1

char *DataProcessingRegisterDisassemble(struct instruction *instruction);

#endif
