#ifndef _BRANCHEXCSYS_H_
#define _BRANCHEXCSYS_H_

#include "common.h"
#include "instruction.h"
#include "utils.h"

static const char *cond_table[] = { 
	"eq,ne", "cs,cc", "mi,pl", "vs,vc",
	"hi,ls", "ge,lt", "gt,le", "al"
};

char *BranchExcSysDisassemble(struct instruction *instruction);


#endif
