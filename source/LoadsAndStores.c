#include "LoadsAndStores.h"
#include <string.h>

int get_post_idx_immediate_offset(int regamount, unsigned int Q){
	if(regamount == 1)
		return Q == 0 ? 8 : 16;
	if(regamount == 2)
		return Q == 0 ? 16 : 32;
	if(regamount == 3)
		return Q == 0 ? 24 : 48;
	if(regamount == 4)
		return Q == 0 ? 32 : 64;

	// should never reach
	return -1;
}

const char *get_arrangement(unsigned int size, unsigned int Q){
	if(size == 0)
		return Q == 0 ? "8b" : "16b";
	if(size == 1)
		return Q == 0 ? "4h" : "8h";
	if(size == 2)
		return Q == 0 ? "2s" : "4s";
	if(size == 3)
		return Q == 0 ? "1d" : "2d";
	
	// should never reach
	return NULL;
}

char *DisassembleLoadStoreMultStructuresInstr(struct instruction *instruction, int postidx){
	char *disassembled = NULL;

	unsigned int Vt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int size = getbitsinrange(instruction->hex, 10, 2);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 4);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int L = getbitsinrange(instruction->hex, 22, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *T = get_arrangement(size, Q);

	if(!T)
		return strdup(".undefined");

	// figure out the register where storing or loading data at/from
	const char *Xn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

	// we need to figure out if this is LDx or STx
	const char *prefix = NULL;

	if(L == 1)
		prefix = "ld";
	else if(L == 0)
		prefix = "st";
	else
		return strdup(".unknown");

	unsigned int selem = 0, regcount = 0;

	// LD4 or ST4 (4 registers)
	if(opcode == 0){
		selem = 4;
		regcount = 4;
	}
	// LD1 or ST1 (4 registers)
	else if(opcode == 2){
		selem = 1;
		regcount = 4;
	}
	// LD3 or ST3 (3 registers)
	else if(opcode == 4){
		selem = 3;
		regcount = 3;
	}
	// LD1 or ST1 (3 registers)
	else if(opcode == 6){
		selem = 1;
		regcount = 3;
	}
	// LD1 or ST1 (1 register)
	else if(opcode == 7){
		selem = 1;
		regcount = 1;
	}
	// LD2 or ST2 (2 registers)
	else if(opcode == 8){
		selem = 2;
		regcount = 2;
	}
	// LD1 or ST1 (2 registers)
	else if(opcode == 0xa){
		selem = 1;
		regcount = 2;
	}
	else
		return strdup(".unknown");

	char *instrtype = malloc(8);
	sprintf(instrtype, "%s%d", prefix, selem);

	// now we can finally start to build the instruction
	disassembled = malloc(512);
	sprintf(disassembled, "%s {", instrtype);

	free(instrtype);

	for(int i=Vt; i<(regcount+Vt); i++)
		sprintf(disassembled, "%s%s.%s, ", disassembled, ARM64_VectorRegisters[i], T);

	// cut off the extra space from the end of the loop
	disassembled[strlen(disassembled) - 2] = '\0';
	
	// append the rest of the instruction
	sprintf(disassembled, "%s}, [%s]", disassembled, Xn);

	// if this is a post-index varient, tack on the
	// post-index register or immediate
	if(postidx){
		// if Rm is not 0x1f, we have a post-index register
		if(Rm != 0x1f)
			sprintf(disassembled, "%s, %s", disassembled, ARM64_GeneralRegisters[Rm]);
		// otherwise, we have a post-index immediate
		else{
			int imm = get_post_idx_immediate_offset(regcount, Q);

			if(imm == -1)
				return strdup(".unknown");

			sprintf(disassembled, "%s, #%d", disassembled, imm);
		}
	}
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleLoadStoreSingleStructuresInstr(struct instruction *instruction, int postidx){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int size = getbitsinrange(instruction->hex, 10, 2);
	unsigned int S = getbitsinrange(instruction->hex, 12, 1);
	unsigned int opcode = getbitsinrange(instruction->hex, 13, 3);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int R = getbitsinrange(instruction->hex, 21, 1);
	unsigned int L = getbitsinrange(instruction->hex, 22, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *Xt = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

	printf("Xt %s\n", Xt);

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *LoadsAndStoresDisassemble(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op0 = getbitsinrange(instruction->hex, 28, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 26, 1);
	unsigned int op2 = getbitsinrange(instruction->hex, 23, 2);
	unsigned int op3 = getbitsinrange(instruction->hex, 16, 6);
	unsigned int op4 = getbitsinrange(instruction->hex, 10, 2);
/*
	print_bin(op0, 4);
	print_bin(op1, 1);
	print_bin(op2, 2);
	print_bin(op3, 6);
	print_bin(op4, 2);
*/
	if(((op0 & 1) == 0 && (op0 & 2) == 0 && (op0 & 8) == 0) && op1 == 1 && (op2 == 0 || op2 == 1) && (op3 >> 5) == 0){
		disassembled = DisassembleLoadStoreMultStructuresInstr(instruction, op2);
	}
	else if((((op0 & 1) == 0 && (op0 & 2) == 0 && (op0 & 8) == 0) && op1 == 1 && (op2 == 2 || op2 == 3))){
		disassembled = DisassembleLoadStoreSingleStructuresInstr(instruction, op2 == 2 ? 0 : 1);
	}
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
