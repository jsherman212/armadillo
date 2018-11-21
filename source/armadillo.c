#include "armadillo.h"


char *disassemble(unsigned int instruction){
	printf("\n");
	
	// very first thing to do is get the encoding for this instruction
	unsigned int op0 = getbitsinrange(instruction, 25, 4);
	
	char *disassembled = NULL;

	//printf("Got op0: ");
	//print_bin(op0, -1);
	//printf("\n");	
	
	unsigned int DataProcessingImmediateMask = 1 << 3;
	//printf("DataProcessingImmediateMask: ");
	//print_bin(DataProcessingImmediateMask);
	
	unsigned int BranchExcSystemMask = (1 << 3) | (1 << 1);
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

	if(op0 == (op0 & DataProcessingImmediateMask)){	
		disassembled = DataProcessingImmediateDisassemble(instruction);
		
		//printf("***DataProcessingImmediate - %s\n", DPIret);
	}
	else if(op0 == (op0 & BranchExcSystemMask)){
		printf("***BranchExcSystemMask\n");

	}
	else if(op0 == (op0 & LoadsAndStoresMask)){
		printf("***LoadsAndStoresMask\n");
	}
	else if(op0 == (op0 & DataProcessingRegisterMask)){
		printf("***DataProcessingRegister\n");

	}
	else if(op0 == (op0 & DataProcessingFloatMask)){
		printf("***DataProcessingFloatMask\n");

	}
	else{
		printf("Unknown decode field \n");
		print_bin(op0, -1);
	}
	//printf("\n");	
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
