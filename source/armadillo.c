#include "armadillo.h"

void print_bin(unsigned int integer){
    int i = CHAR_BIT * sizeof integer; /* however many bits are in an integer */
    while(i--) {
        putchar('0' + ((integer >> i) & 1)); 
    }

	printf("\n");
}

char *disassemble(unsigned int instruction){
	// very first thing to do is get the encoding for this instruction
	unsigned int op0 = getbitsinrange(instruction, 25, 4);

	printf("Got op0: ");
	print_bin(op0);
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
		char *DPIret = DataProcessingImmediateDisassemble(instruction);
		
		printf("***DataProcessingImmediate - %s\n", DPIret);
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
		print_bin(op0);
	}
	printf("\n");	
	
	/*//op0 = 0b1001;
	//op0 = 0;
	
	//printf("%d\n", op0 & (0b1000 | 0b0001));
	
	// 100x
	unsigned int DataProcessingImmediateMask = 0b1000;
	printf("%d\n", DataProcessingImmediateMask);	
	// Data Processing - Immediate
	if(op0 == (op0 & DataProcessingImmediateMask)){
		char *DPIret = DataProcessingImmediateDisassemble(instruction);
		
		printf("DataProcessingImmediate - %s\n", DPIret);
	}
	else
		printf("Nope\n");
*/
	return "no result";
}
