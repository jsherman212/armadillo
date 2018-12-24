#include "armadillo.h"

char *_ArmadilloDisassemble(struct instruction *instr){
	printf("\n");
	
	// very first thing to do is get the encoding for this instruction
	unsigned int op0 = getbitsinrange(instr->hex, 25, 4);
	//print_bin(op0, -1);
	char *disassembled = NULL;

	//printf("Got op0: ");
	//print_bin(op0, -1);
	//printf("\n");
	
	unsigned int DataProcessingImmediateMask = (1 << 3) >> 1/*| 1*/;
	//printf("DataProcessingImmediateMask: ");
	//print_bin(DataProcessingImmediateMask);
	
	unsigned int BranchExcSystemMask = (1 << 3) | (1 << 1) | 1; // was just (1 << 3) | (1 << 1) before
	//printf("BranchExcSystemMask: ");
	//print_bin(BranchExcSystemMask);

	unsigned int LoadsAndStoresMask = 1 << 2;
	//printf("LoadsAndStoresMask: ");
	//print_bin(LoadsAndStoresMask);

	unsigned int DataProcessingRegisterMask = (1 << 2) | 1;
	//printf("DataProcessingRegisterMask: ");
	//print_bin(DataProcessingRegisterMask);
	
	unsigned int DataProcessingFloatMask = (1 << 2) | (1 << 1) | 1;	
	//printf("DataProcessingFloatMask: ");
	//print_bin(DataProcessingFloatMask);

	//print_bin((op0 & ~0x8), 4);

	if(op0 == 0)
		return strdup(".undefined");
	if((op0 >> 1) == DataProcessingImmediateMask){
		//printf("***DataProcessingImmediate\n");
		disassembled = DataProcessingImmediateDisassemble(instr);
		
		//printf("***DataProcessingImmediate - %s\n", DPIret);
	}
	else if(op0 == (op0 & BranchExcSystemMask)){
		//printf("***BranchExcSystemMask\n");
		disassembled = BranchExcSysDisassemble(instr);
	}
	else if(((op0 >> 2) & 1) == 1 && (op0 & 1) == 0){
		//printf("***LoadsAndStoresMask\n");
		disassembled = LoadsAndStoresDisassemble(instr);
	}
	else if((op0 & ~0x8) == 5){//== (op0 & DataProcessingRegisterMask)){
		//printf("***DataProcessingRegister\n");
		disassembled = DataProcessingRegisterDisassemble(instr);
	}
	else if((op0 & ~0x8) == 7){//== (op0 & DataProcessingFloatMask)){
		//printf("***DataProcessingFloatMask\n");
		disassembled = DataProcessingFloatingPointDisassemble(instr);
	}
	else{
		printf("Unknown decode field \n");
		print_bin(op0, -1);
	}
	//printf("\n");	
	
	//printf("ArmadilloDisassemble: ret = %p\n", disassembled);

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
