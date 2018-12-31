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

#include "armadillo.h"

char *_ArmadilloDisassemble(struct instruction *instr){
	unsigned int op0 = getbitsinrange(instr->hex, 25, 4);

	char *disassembled = NULL;

	if(op0 == 0)
		return strdup(".undefined");
	else if(op0 == 1)
		return strdup(".undefined");
	else if((op0 & ~0x1) == 0x2)
		return strdup(".undefined");
	else if((op0 & ~0x1) == 0x8)
		disassembled = DataProcessingImmediateDisassemble(instr);
	else if((op0 & ~0x1) == 0xa)
		disassembled = BranchExcSysDisassemble(instr);
	else if((op0 & ~0xa) == 0x4)
		disassembled = LoadsAndStoresDisassemble(instr);
	else if((op0 & ~0x8) == 0x5)
		disassembled = DataProcessingRegisterDisassemble(instr);
	else if((op0 & ~0x8) == 0x7)
		disassembled = DataProcessingFloatingPointDisassemble(instr);
	else
		return strdup(".unknown");

	return disassembled;
}

unsigned int CFSwapInt32(unsigned int arg) {
	unsigned int result;
  	result = ((arg & 0xFF) << 24) | ((arg & 0xFF00) << 8) | ((arg >> 8) & 0xFF00) | ((arg >> 24) & 0xFF);
  	return result;
}

char *ArmadilloDisassemble(unsigned int hex, unsigned long PC){
	struct instruction *instr = instruction_new(hex, PC);
	char *disassembled = _ArmadilloDisassemble(instr);
	free(instr);
	return disassembled;
}

char *ArmadilloDisassembleB(unsigned int hex, unsigned long PC){
	return ArmadilloDisassemble(CFSwapInt32(hex), PC);
}
