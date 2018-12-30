#include "armadillo.h"

char *_ArmadilloDisassemble(struct instruction *instr){
	// very first thing to do is get the encoding for this instruction
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
	else{
		printf("Unknown decode field \n");
		print_bin(op0, -1);
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *ArmadilloDisassemble(unsigned int hex, unsigned long PC){
	struct instruction *instr = instruction_new(hex, PC);
	char *disassembled = _ArmadilloDisassemble(instr);
	free(instr);
	return disassembled;
}
