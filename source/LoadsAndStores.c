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
	disassembled = malloc(256);
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


// TODO optimize
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
	
	int scale = getbitsinrange(opcode, 1, 2);
	int selem = (((opcode & 1) << 1) | R) + 1;
	
	//printf("selem: %d\n", selem);

	char *instr = NULL;
	const char *suffix = NULL;
	
	int index = 0;

	switch(scale){
		case 3:
		{
			// load and replicate
			if(L == 0 && S == 1){
				free(instr);
				return strdup(".undefined");
			}
			
			scale = size;
			
			if(!instr){
				instr = malloc(8);
				sprintf(instr, "ld%dr", selem);
			}

			break;
		}
		case 0: // B[0-15]
			index = (Q << 3) | (S << 2) | size;
			suffix = "b";
			//printf("index: %d\n", index);
			break;
		case 1: // H[0-7]
			if((size & 1) == 1)
				return strdup(".undefined");

			index = (Q << 2) | (S << 1) | (size >> 1);
			suffix = "h";
			break;
		case 2:
		{
			if(((size << 1) & 1) == 1)
				return strdup(".undefined");
			
			// S[0-3]
			if((size & 1) == 0){
				index = (Q << 1) | S;
				suffix = "s";
			}
			// D[0-1]
			else{
				if(S == 1)
					return strdup(".undefined");

				index = Q;
				suffix = "d";
				scale = 3;
			}

			break;
		}
	};

	//printf("index %d, suffix %s\n", index, suffix);
	
	disassembled = malloc(256);

	// we can get the post index immediate
	// by multipling whatever index
	// corresponds with our suffix by selem
	int ldstimms[] = {1, 2, 4, 8};
	
	// figure out instruction type
	// if it hasn't been initialized yet, it's not
	// a load and replicate
	if(!instr){
		instr = malloc(8);

		if(L == 0)
			sprintf(instr, "st%d", selem);
		else
			sprintf(instr, "ld%d", selem);

		sprintf(disassembled, "%s {", instr);
		free(instr);
		
		for(int i=Rt; i<(Rt+selem); i++)
			sprintf(disassembled, "%s%s.%s, ", disassembled, ARM64_VectorRegisters[i], suffix);
		
		// remove the extra space at the end
		disassembled[strlen(disassembled) - 2] = '\0';
		
		const char *Xn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		// build the rest of the instruction
		sprintf(disassembled, "%s}[%d], [%s]", disassembled, index, Xn);
		
		// check for any post-index stuff
		if(postidx){
			// if Rm is not 0x1f, we have a post index register
			if(Rm != 0x1f)
				sprintf(disassembled, "%s, %s", disassembled, ARM64_GeneralRegisters[Rm]);
			else{
				// assume we have an 8 bit varient
				int immidx = 0;

				if(strcmp(suffix, "h") == 0)
					immidx = 1;
				else if(strcmp(suffix, "s") == 0)
					immidx = 2;
				else if(strcmp(suffix, "d") == 0)
					immidx = 3;

				sprintf(disassembled, "%s, #%d", disassembled, ldstimms[immidx] * selem);
			}
		}
	}
	// it's a load and replicate
	else{
		const char *T = get_arrangement(size, Q);

		if(!T){
			free(disassembled);
			free(instr);
			return strdup(".undefined");
		}

		sprintf(disassembled, "%s {", instr);
		free(instr);
	
		for(int i=Rt; i<(Rt+selem); i++)
			sprintf(disassembled, "%s%s.%s, ", disassembled, ARM64_VectorRegisters[i], T);

		disassembled[strlen(disassembled) - 2] = '\0';

		const char *Xn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s}, [%s]", disassembled, Xn);

		if(postidx){
			if(Rm != 0x1f)
				sprintf(disassembled, "%s, %s", disassembled, ARM64_GeneralRegisters[Rm]);
			else{
				sprintf(disassembled, "%s, #%d", disassembled, ldstimms[selem] * selem);
			}
		}
	}
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleLoadAndStoreExclusiveInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int Rt2 = getbitsinrange(instruction->hex, 10, 5);
	unsigned int o0 = getbitsinrange(instruction->hex, 15, 1);
	unsigned int Rs = getbitsinrange(instruction->hex, 16, 5);
	unsigned int o1 = getbitsinrange(instruction->hex, 21, 1);
	unsigned int L = getbitsinrange(instruction->hex, 22, 1);
	unsigned int o2 = getbitsinrange(instruction->hex, 23, 1);
	unsigned int size = getbitsinrange(instruction->hex, 30, 2);
	unsigned int sz = getbitsinrange(instruction->hex, 30, 1);

	unsigned int encoding = (o2 << 3) | (L << 2) | (o1 << 1) | o0;

	const char **registers = ARM64_32BitGeneralRegisters;

	if(size == 3)
		registers = ARM64_GeneralRegisters;
	
	disassembled = malloc(128);
	sprintf(disassembled, ".unknown");
	
	if(encoding == 0){
		// another stxr in case it is the 64 bit version
		const char *instr_tbl[] = {"stxrb", "stxrh", "stxr", "stxr"};
		
		const char *_Rs = ARM64_32BitGeneralRegisters[Rs];
		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, %s, [%s]", instr_tbl[size], _Rs, _Rt, _Rn);
	}
	else if(encoding == 1){
		const char *instr_tbl[] = {"stlxrb", "stlxrh", "stlxr", "stlxr"};

		const char *_Rs = ARM64_32BitGeneralRegisters[Rs];
		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, %s, [%s]", instr_tbl[size], _Rs, _Rt, _Rn);
	}
	else if(encoding == 2 || encoding == 3){
		const char *_Rs = ARM64_32BitGeneralRegisters[Rs];
		const char *_Rt1 = registers[Rt];
		const char *_Rt2 = registers[Rt2];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, %s, %s, [%s]", encoding == 2 ? "stxp" : "stlxp", _Rs, _Rt1, _Rt2, _Rn);
	}
	else if(encoding == 4){
		const char *instr_tbl[] = {"ldxrb", "ldxrh", "ldxr", "ldxr"};
		
		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
	}
	else if(encoding == 5){
		const char *instr_tbl[] = {"ldaxrb", "ldaxrh", "ldaxr", "ldaxr"};
		
		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
	}
	else if(encoding == 6 || encoding == 7){
		if(Rt2 == 0x1f){
			if(sz == 1)
				registers = ARM64_GeneralRegisters;

			const char *_Rs = registers[Rs];
			const char *_Rs2 = registers[Rs + 1];
			const char *_Rt = registers[Rt];
			const char *_Rt2 = registers[Rt + 1];
			const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

			sprintf(disassembled, "%s %s, %s, %s, %s, [%s]", encoding == 6 ? "caspa" : "caspal", _Rs, _Rs2, _Rt, _Rt2, _Rn);
		}
		else{
			const char *_Rt1 = registers[Rt];
			const char *_Rt2 = registers[Rt2];
			const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];
			
			sprintf(disassembled, "%s %s, %s, [%s]", encoding == 6 ? "ldxp" : "ldaxp", _Rt1, _Rt2, _Rn);
		}
	}
	else if(encoding == 8){
		const char *instr_tbl[] = {"stllrb", "stllrh", "stllr", "stllr"};

		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
	}
	else if(encoding == 9){
		const char *instr_tbl[] = {"stlrb", "stlrh", "stlr", "stlr"};

		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
	}
	else if((encoding == 10 || encoding == 11 || encoding == 14 || encoding == 15) && Rt2 == 0x1f){
		const char **registers = ARM64_32BitGeneralRegisters;

		if(size == 3)
			registers = ARM64_GeneralRegisters;
		
		const char *_Rs = registers[Rs];
		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		const char *instr = size == 1 ? "cash" : "cas";

		if(encoding == 11)
			instr = (size == 2 || size == 3) ? "casl" : "caslh";
		else if(encoding == 14)
			instr = (size == 2 || size == 3) ? "casa" : "casah";
		else if(encoding == 15)
			instr = (size == 2 || size == 3) ? "casal" : "casalh";

		sprintf(disassembled, "%s %s, %s, [%s]", instr, _Rs, _Rt, _Rn);
	}
	else if(encoding == 12){
		const char *instr_tbl[] = {"ldlarb", "ldlarh", "ldlar", "ldlar"};

		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
	}
	else if(encoding == 13){
		const char *instr_tbl[] = {"ldarb", "ldarh", "ldar", "ldar"};

		const char *_Rt = registers[Rt];
		const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

		sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
	}

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
	else if(((op0 & 1) == 0 && (op0 & 2) == 0) && op1 == 0 && (op2 >> 1) == 0){
		disassembled = DisassembleLoadAndStoreExclusiveInstr(instruction);
	}
	else
		return strdup(".undefined");
	
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
