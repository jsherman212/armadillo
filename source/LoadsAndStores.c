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
			else
				sprintf(disassembled, "%s, #%d", disassembled, ldstimms[selem] * selem);
		}
	}
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

/***********************

00:0:0:0:0:-
STXRB <Ws>, <Wt>, [<Xn|SP>{,#0}] 

01:0:0:0:0:-
STXRH <Ws>, <Wt>, [<Xn|SP>{,#0}] 

10:0:0:0:0:-
STXR <Ws>, <Wt>, [<Xn|SP>{,#0}] 

11:0:0:0:0:-
STXR <Ws>, <Xt>, [<Xn|SP>{,#0}] 

-----------------------

00:0:0:0:1:-
STLXRB <Ws>, <Wt>, [<Xn|SP>{,#0}] 

01:0:0:0:1:-
STLXRH <Ws>, <Wt>, [<Xn|SP>{,#0}] 

10:0:0:0:1:-
STLXR <Ws>, <Wt>, [<Xn|SP>{,#0}] 

11:0:0:0:1-
STLXR <Ws>, <Xt>, [<Xn|SP>{,#0}] 

-----------------------

10:0:0:1:0:-
STXP <Ws>, <Wt1>, <Wt2>, [<Xn|SP>{,#0}] 

11:0:0:1:0:-
STXP <Ws>, <Xt1>, <Xt2>, [<Xn|SP>{,#0}] 

-----------------------

10:0:0:1:1:-
STLXP <Ws>, <Wt1>, <Wt2>, [<Xn|SP>{,#0}] 

11:0:0:1:1:-
STLXP <Ws>, <Xt1>, <Xt2>, [<Xn|SP>{,#0}] 

-----------------------

00:0:1:0:0:-
LDXRB <Wt>, [<Xn|SP>{,#0}] 

01:0:1:0:0:-
LDXRH <Wt>, [<Xn|SP>{,#0}]

10:0:1:0:0:-
LDXR <Wt>, [<Xn|SP>{,#0}] 

11:0:1:0:0:-
LDXR <Xt>, [<Xn|SP>{,#0}] 

-----------------------

00:0:1:0:1:-
LDAXRB <Wt>, [<Xn|SP>{,#0}] 

01:0:1:0:1:-
LDAXRH <Wt>, [<Xn|SP>{,#0}] 

10:0:1:0:1:-
LDAXR <Wt>, [<Xn|SP>{,#0}] 

11:0:1:0:1:-
LDAXR <Xt>, [<Xn|SP>{,#0}] 

-----------------------

10:0:1:1:0:-
LDXP <Wt1>, <Wt2>, [<Xn|SP>{,#0}]

11:0:1:1:0:-
LDXP <Xt1>, <Xt2>, [<Xn|SP>{,#0}] 

-----------------------

10:0:1:1:1:-
LDAXP <Wt1>, <Wt2>, [<Xn|SP>{,#0}] 

11:0:1:1:1:-
LDAXP <Xt1>, <Xt2>, [<Xn|SP>{,#0}] 

-----------------------

00:1:0:0:0:-
STLLRB <Wt>, [<Xn|SP>{,#0}] 

01:1:0:0:0:-
STLLRH <Wt>, [<Xn|SP>{,#0}] 

10:1:0:0:0:-
STLLR <Wt>, [<Xn|SP>{,#0}] 

11:1:0:0:0:-
STLLR <Xt>, [<Xn|SP>{,#0}] 

-----------------------

00:1:0:0:1:-
STLRB <Wt>, [<Xn|SP>{,#0}] 

01:1:0:0:1:-
STLRH <Wt>, [<Xn|SP>{,#0}] 

10:1:0:0:1:-
STLR <Wt>, [<Xn|SP>{,#0}] 

11:1:0:0:1-
STLR <Xt>, [<Xn|SP>{,#0}] 

-----------------------

00:1:1:0:0:-
LDLARB <Wt>, [<Xn|SP>{,#0}] 

01:1:1:0:0:-
LDLARH <Wt>, [<Xn|SP>{,#0}] 

10:1:1:0:0:-
LDLAR <Wt>, [<Xn|SP>{,#0}] 

11:1:1:0:0:-
LDLAR <Xt>, [<Xn|SP>{,#0}] 

-----------------------

00:1:1:0:1:-
LDARB <Wt>, [<Xn|SP>{,#0}] 

01:1:1:0:1:-
LDARH <Wt>, [<Xn|SP>{,#0}] 

10:1:1:0:1:-
LDAR <Wt>, [<Xn|SP>{,#0}] 

11:1:1:0:1-
LDAR <Xt>, [<Xn|SP>{,#0}] 

-----------------------
***********************/

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

	return disassembled;
}

char *DisassembleLoadAndStoreLiteralInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int imm19 = getbitsinrange(instruction->hex, 5, 19);
	unsigned int V = getbitsinrange(instruction->hex, 26, 1);
	unsigned int opc = getbitsinrange(instruction->hex, 30, 2);

	if(opc == 3 && V == 1)
		return strdup(".undefined");

	const char **general_registers = ARM64_GeneralRegisters;
	const char **flt_registers = ARM64_VectorQRegisters;

	if(opc == 0){
		general_registers = ARM64_32BitGeneralRegisters;
		flt_registers = ARM64_VectorSinglePrecisionRegisters;
	}
	else if(opc == 1)
		flt_registers = ARM64_VectorDoublePrecisionRegisters;
	
	if(opc == 3 && V == 0){
		disassembled = malloc(128);

		const char *types[] = {"PLD", "PLI", "PST"};
		const char *targets[] = {"L1", "L2", "L3"};
		const char *policies[] = {"KEEP", "STRM"};

		unsigned int type = getbitsinrange(Rt, 3, 1);
		unsigned int target = getbitsinrange(Rt, 1, 1);
		unsigned int policy = Rt & 1;

		imm19 = sign_extend(imm19, 19);

		if(type > 2 || target > 2 || policy > 1)
			sprintf(disassembled, "prfm #%#x, #%#lx", Rt, (signed int)imm19 + instruction->PC);
		else
			sprintf(disassembled, "prfm %s%s%s, #%#lx", types[type], targets[target], policies[policy], (signed int)imm19 + instruction->PC);
	}
	else{
		const char *instr = "ldr";

		if(opc == 2 && V == 0)
			instr = "ldrsw";

		if(V == 0){
			disassembled = malloc(128);

			imm19 = sign_extend((imm19 << 2), 21);
			
			sprintf(disassembled, "%s %s, #%#lx", instr, general_registers[Rt], (signed int)imm19 + instruction->PC);
		}
		else{
			disassembled = malloc(128);

			imm19 = sign_extend((imm19 << 2), 21);
			
			sprintf(disassembled, "%s %s, #%#lx", instr, flt_registers[Rt], (signed int)imm19 + instruction->PC);
		}
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleLoadAndStoreRegisterPairInstr(struct instruction *instruction, int kind){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int Rt2 = getbitsinrange(instruction->hex, 10, 5);
	int imm7 = getbitsinrange(instruction->hex, 15, 7);
	unsigned int L = getbitsinrange(instruction->hex, 22, 1);
	unsigned int V = getbitsinrange(instruction->hex, 26, 1);
	unsigned int opc = getbitsinrange(instruction->hex, 30, 2);
	
	const char **registers = ARM64_32BitGeneralRegisters;

	if(opc == 0)
		registers = V == 0 ? registers : ARM64_VectorSinglePrecisionRegisters;
	else if(opc == 1)
		registers = V == 0/*L==1*/ ? ARM64_GeneralRegisters : ARM64_VectorDoublePrecisionRegisters;
	else if(opc == 2)
		registers = V == 0 ? ARM64_GeneralRegisters : ARM64_VectorQRegisters;

	disassembled = malloc(128);
	bzero(disassembled, 128);

	int scale = 0;

	// if V is 0, we're not dealing with floating point registers
	if(V == 0)
		scale = 2 + (opc >> 1);
	else
		scale = 2 + opc;

	imm7 = sign_extend(imm7, 7) << scale;
	
	char *instr = malloc(8);
	sprintf(instr, "st");

	if(L == 1)
		sprintf(instr, "%s", (V == 0 && opc == 1) ? "ldpsw" : "ld");

	if(strcmp(instr, "ldpsw") != 0)
		sprintf(instr, "%s%sp", instr, kind == NO_ALLOCATE ? "n" : "");

	const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

	sprintf(disassembled, "%s %s, %s, [%s", instr, registers[Rt], registers[Rt2], _Rn);
	free(instr);

	// check whether or not we need to append an immediate
	if(imm7 == 0)
		sprintf(disassembled, "%s]", disassembled);
	else if(kind == POST_INDEXED)
		sprintf(disassembled, "%s], #%#x", disassembled, imm7);
	else if(kind == OFFSET || kind == NO_ALLOCATE)
		sprintf(disassembled, "%s, #%#x]", disassembled, imm7);
	else if(kind == PRE_INDEXED)
		sprintf(disassembled, "%s, #%#x]!", disassembled, imm7);
	
	return disassembled;
}

char *DisassembleLoadAndStoreRegisterInstr(struct instruction *instruction, int kind){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	int imm12 = getbitsinrange(instruction->hex, 10, 12);
	int imm9 = imm12 >> 2;
	unsigned int opc = getbitsinrange(instruction->hex, 22, 2);
	unsigned int V = getbitsinrange(instruction->hex, 26, 1);
	unsigned int size = getbitsinrange(instruction->hex, 30, 2);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(V == 0 && (opc == 2 || size == 3))
		registers = ARM64_GeneralRegisters;
	else if(V == 1){
		if(size == 0 && (opc == 0 || opc == 1))
			registers = ARM64_VectorBRegisters;
		else if(size == 0 && (opc == 2 || opc == 3))
			registers = ARM64_VectorQRegisters;
		else if(size == 1 && (opc == 0 || opc == 1))
			registers = ARM64_VectorHalfPrecisionRegisters;
		else if(size == 2 && (opc == 0 || opc == 1))
			registers = ARM64_VectorSinglePrecisionRegisters;
		else if(size == 3 && (opc == 0 || opc == 1))
			registers = ARM64_VectorDoublePrecisionRegisters;
	}

	const char **instr_tbl = unscaled_instr_tbl;

	if(kind == UNSIGNED_IMMEDIATE || kind == IMMEDIATE_POST_INDEXED || kind == IMMEDIATE_PRE_INDEXED)
		instr_tbl = pre_post_unsigned_register_idx_instr_tbl;
	else if(kind == UNPRIVILEGED)
		instr_tbl = unprivileged_instr_tbl;

	unsigned int instr_idx = (size << 3) | (V << 2) | opc;
	
	const char *instr = instr_tbl[instr_idx];

	if(!instr)
		return strdup(".undefined");

	imm9 = sign_extend(imm9, 9);

	disassembled = malloc(128);
	
	const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

	if(strcmp(instr, "prfm") == 0){
		const char *types[] = {"PLD", "PLI", "PST"};
		const char *targets[] = {"L1", "L2", "L3"};
		const char *policies[] = {"KEEP", "STRM"};

		unsigned int type = getbitsinrange(Rt, 3, 1);
		unsigned int target = getbitsinrange(Rt, 1, 1);
		unsigned int policy = Rt & 1;

		if(type > 2 || target > 2 || policy > 1)
			sprintf(disassembled, "%s #%#x, #%#lx", instr, Rt, imm9 + instruction->PC);
		else
			sprintf(disassembled, "%s %s%s%s, #%#lx", instr, types[type], targets[target], policies[policy], imm9 + instruction->PC);

		return disassembled;
	}

	sprintf(disassembled, "%s %s, [%s", instr, registers[Rt], _Rn);
	
	if(kind == UNSCALED_IMMEDIATE || kind == UNPRIVILEGED){
		if(imm9 == 0)
			sprintf(disassembled, "%s]", disassembled);
		else
			sprintf(disassembled, "%s, #%#x]", disassembled, imm9);
	}
	else if(kind == UNSIGNED_IMMEDIATE){
		imm12 = sign_extend(imm12, 12);

		if(imm12 == 0)
			sprintf(disassembled, "%s]", disassembled);
		else{
			if((opc >> 1) == 0)
				imm12 <<= ((opc >> 1) | size);
			
			sprintf(disassembled, "%s, #%#x]", disassembled, imm12);
		}
	}
	else if(kind == IMMEDIATE_POST_INDEXED)
		sprintf(disassembled, "%s], #%#x", disassembled, imm9);
	else if(kind == IMMEDIATE_PRE_INDEXED)
		sprintf(disassembled, "%s, #%#x]!", disassembled, imm9);
	
	return disassembled;
}

char *get_atomic_memory_instr(unsigned int size, unsigned int V, unsigned int A, unsigned int R, unsigned int o3, unsigned int opc){
	unsigned int encoding = size << 7;
	encoding |= V << 6;
	encoding |= A << 5;
	encoding |= R << 4;
	encoding |= o3 << 3;
	encoding |= opc;

	// auto generated
	// [a-zA-Z0-9]+(?=\s?variant)
	switch(encoding){
	case 0x0:
		return "ldaddb";
	case 0x1:
		return "ldclrb";
	case 0x2:
		return "ldeorb";
	case 0x3:
		return "ldsetb";
	case 0x4:
		return "ldsmaxb";
	case 0x5:
		return "ldsminb";
	case 0x6:
		return "ldumaxb";
	case 0x7:
		return "lduminb";
	case 0x8:
		return "swpb";
	case 0x10:
		return "ldaddlb";
	case 0x11:
		return "ldclrlb";
	case 0x12:
		return "ldeorlb";
	case 0x13:
		return "ldsetlb";
	case 0x14:
		return "ldsmaxlb";
	case 0x15:
		return "ldsminlb";
	case 0x16:
		return "ldumaxlb";
	case 0x17:
		return "lduminlb";
	case 0x18:
		return "swplb";
	case 0x20:
		return "ldaddab";
	case 0x21:
		return "ldclrab";
	case 0x22:
		return "ldeorab";
	case 0x23:
		return "ldsetab";
	case 0x24:
		return "ldsmaxab";
	case 0x25:
		return "ldsminab";
	case 0x26:
		return "ldumaxab";
	case 0x27:
		return "lduminab";
	case 0x28:
		return "swpab";
	case 0x2c:
		return "ldaprb";
	case 0x30:
		return "ldaddalb";
	case 0x31:
		return "ldclralb";
	case 0x32:
		return "ldeoralb";
	case 0x33:
		return "ldsetalb";
	case 0x34:
		return "ldsmaxalb";
	case 0x35:
		return "ldsminalb";
	case 0x36:
		return "ldumaxalb";
	case 0x37:
		return "lduminalb";
	case 0x38:
		return "swpalb";
	case 0x80:
		return "ldaddh";
	case 0x81:
		return "ldclrh";
	case 0x82:
		return "ldeorh";
	case 0x83:
		return "ldseth";
	case 0x84:
		return "ldsmaxh";
	case 0x85:
		return "ldsminh";
	case 0x86:
		return "ldumaxh";
	case 0x87:
		return "lduminh";
	case 0x88:
		return "swph";
	case 0x90:
		return "ldaddlh";
	case 0x91:
		return "ldclrlh";
	case 0x92:
		return "ldeorlh";
	case 0x93:
		return "ldsetlh";
	case 0x94:
		return "ldsmaxlh";
	case 0x95:
		return "ldsminlh";
	case 0x96:
		return "ldumaxlh";
	case 0x97:
		return "lduminlh";
	case 0x98:
		return "swplh";
	case 0xa0:
		return "ldaddah";
	case 0xa1:
		return "ldclrah";
	case 0xa2:
		return "ldeorah";
	case 0xa3:
		return "ldsetah";
	case 0xa4:
		return "ldsmaxah";
	case 0xa5:
		return "ldsminah";
	case 0xa6:
		return "ldumaxah";
	case 0xa7:
		return "lduminah";
	case 0xa8:
		return "swpah";
	case 0xac:
		return "ldaprh";
	case 0xb0:
		return "ldaddalh";
	case 0xb1:
		return "ldclralh";
	case 0xb2:
		return "ldeoralh";
	case 0xb3:
		return "ldsetalh";
	case 0xb4:
		return "ldsmaxalh";
	case 0xb5:
		return "ldsminalh";
	case 0xb6:
		return "ldumaxalh";
	case 0xb7:
		return "lduminalh";
	case 0xb8:
		return "swpalh";
	case 0x100:
		return "ldadd";
	case 0x101:
		return "ldclr";
	case 0x102:
		return "ldeor";
	case 0x103:
		return "ldset";
	case 0x104:
		return "ldsmax";
	case 0x105:
		return "ldsmin";
	case 0x106:
		return "ldumax";
	case 0x107:
		return "ldumin";
	case 0x108:
		return "swp";
	case 0x110:
		return "ldaddl";
	case 0x111:
		return "ldclrl";
	case 0x112:
		return "ldeorl";
	case 0x113:
		return "ldsetl";
	case 0x114:
		return "ldsmaxl";
	case 0x115:
		return "ldsminl";
	case 0x116:
		return "ldumaxl";
	case 0x117:
		return "lduminl";
	case 0x118:
		return "swpl";
	case 0x120:
		return "ldadda";
	case 0x121:
		return "ldclra";
	case 0x122:
		return "ldeora";
	case 0x123:
		return "ldseta";
	case 0x124:
		return "ldsmaxa";
	case 0x125:
		return "ldsmina";
	case 0x126:
		return "ldumaxa";
	case 0x127:
		return "ldumina";
	case 0x128:
		return "swpa";
	case 0x12c:
		return "ldapr";
	case 0x130:
		return "ldaddal";
	case 0x131:
		return "ldclral";
	case 0x132:
		return "ldeoral";
	case 0x133:
		return "ldsetal";
	case 0x134:
		return "ldsmaxal";
	case 0x135:
		return "ldsminal";
	case 0x136:
		return "ldumaxal";
	case 0x137:
		return "lduminal";
	case 0x138:
		return "swpal";
	case 0x180:
		return "ldadd";
	case 0x181:
		return "ldclr";
	case 0x182:
		return "ldeor";
	case 0x183:
		return "ldset";
	case 0x184:
		return "ldsmax";
	case 0x185:
		return "ldsmin";
	case 0x186:
		return "ldumax";
	case 0x187:
		return "ldumin";
	case 0x188:
		return "swp";
	case 0x190:
		return "ldaddl";
	case 0x191:
		return "ldclrl";
	case 0x192:
		return "ldeorl";
	case 0x193:
		return "ldsetl";
	case 0x194:
		return "ldsmaxl";
	case 0x195:
		return "ldsminl";
	case 0x196:
		return "ldumaxl";
	case 0x197:
		return "lduminl";
	case 0x198:
		return "swpl";
	case 0x1a0:
		return "ldadda";
	case 0x1a1:
		return "ldclra";
	case 0x1a2:
		return "ldeora";
	case 0x1a3:
		return "ldseta";
	case 0x1a4:
		return "ldsmaxa";
	case 0x1a5:
		return "ldsmina";
	case 0x1a6:
		return "ldumaxa";
	case 0x1a7:
		return "ldumina";
	case 0x1a8:
		return "swpa";
	case 0x1ac:
		return "ldapr";
	case 0x1b0:
		return "ldaddal";
	case 0x1b1:
		return "ldclral";
	case 0x1b2:
		return "ldeoral";
	case 0x1b3:
		return "ldsetal";
	case 0x1b4:
		return "ldsmaxal";
	case 0x1b5:
		return "ldsminal";
	case 0x1b6:
		return "ldumaxal";
	case 0x1b7:
		return "lduminal";
	case 0x1b8:
		return "swpal";
	default:
		return NULL;
	};
}

char *DisassembleAtomicMemoryInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opc = getbitsinrange(instruction->hex, 12, 3);
	unsigned int o3 = getbitsinrange(instruction->hex, 15, 1);
	unsigned int Rs = getbitsinrange(instruction->hex, 16, 5);
	unsigned int R = getbitsinrange(instruction->hex, 22, 1);
	unsigned int A = getbitsinrange(instruction->hex, 23, 1);
	unsigned int V = getbitsinrange(instruction->hex, 26, 1);
	unsigned int size = getbitsinrange(instruction->hex, 30, 2);

	const char *instr = get_atomic_memory_instr(size, V, A, R, o3, opc);
	
	if(!instr)
		return strdup(".undefined");
	
	const char **registers = ARM64_32BitGeneralRegisters;

	if(size == 3)
		registers = ARM64_GeneralRegisters;

	const char *_Rs = registers[Rs];
	const char *_Rt = registers[Rt];
	const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];
	
	disassembled = malloc(128);

	if(strcmp(instr, "ldapr") != 0 && strcmp(instr, "ldaprb") != 0 && strcmp(instr, "ldaprh") != 0)
		sprintf(disassembled, "%s %s, %s, [%s]", instr, _Rs, _Rt, _Rn);
	else
		sprintf(disassembled, "%s %s, [%s]", instr, _Rt, _Rn);
	
	return disassembled;
}

char *decode_reg_extend(unsigned int op){
	switch(op){
	case 0x0:
		return "uxtb";
	case 0x1:
		return "uxth";
	case 0x2:
		return "uxtw";
	case 0x3:
		return "uxtx";
	case 0x4:
		return "sxtb";
	case 0x5:
		return "sxth";
	case 0x6:
		return "sxtw";
	case 0x7:
		return "sxtx";
	default:
		return NULL;
	};
}

char *DisassembleLoadAndStoreRegisterOffsetInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int S = getbitsinrange(instruction->hex, 12, 1);
	unsigned int option = getbitsinrange(instruction->hex, 13, 3);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int opc = getbitsinrange(instruction->hex, 22, 2);
	unsigned int V = getbitsinrange(instruction->hex, 26, 1);
	unsigned int size = getbitsinrange(instruction->hex, 30, 2);

	const char **general_registers = ARM64_32BitGeneralRegisters;
	const char **flt_registers = ARM64_VectorQRegisters;
	
	int _64bit = 0;
	int amount = 0;
	
	// default to 128 bit
	int flt_amount = S == 0 ? 0 : 4;

	if(V == 0 && (opc == 2 || size == 3)){
		general_registers = ARM64_GeneralRegisters;
		_64bit = 1;
	}
	else if(V == 1){
		if(size == 0 && opc != 2){
			flt_registers = ARM64_VectorBRegisters;
			
			// this doesn't matter here
			flt_amount = -1;
		}
		else if(size == 1){
			flt_registers = ARM64_VectorHalfPrecisionRegisters;
			flt_amount = S == 0 ? 0 : 1;
		}
		else if(size == 2){
			flt_registers = ARM64_VectorSinglePrecisionRegisters;
			flt_amount = S == 0 ? 0 : 2;
		}
		else if(size == 3){
			flt_registers = ARM64_VectorDoublePrecisionRegisters;
			flt_amount = S == 0 ? 0 : 3;
		}
	}

	const char *_Rt = NULL;

	if(V == 1)
		_Rt = flt_registers[Rt];
	else
		_Rt = general_registers[Rt];

	const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];
	const char *_Rm = ARM64_32BitGeneralRegisters[Rm];

	if((option & 1) == 1)
		_Rm = ARM64_GeneralRegisters[Rm];
	
	int extended = option != 3 ? 1 : 0;
	const char *extend = NULL;

	if(extended)
		extend = decode_reg_extend(option);
	
	const char **instr_tbl = pre_post_unsigned_register_idx_instr_tbl;
	
	unsigned int instr_idx = (size << 3) | (V << 2) | opc;
	const char *instr = instr_tbl[instr_idx];
	
	if(!instr)
		return strdup(".undefined");
	
	int omit_amount = -1;

	disassembled = malloc(128);
	sprintf(disassembled, "%s %s, [%s, %s", instr, _Rt, _Rn, _Rm);
	
	omit_amount = S == 0 ? 1 : 0;
	
	if(V == 0){
		amount = S;
		
		if(strcmp(instr, "strb") == 0 || strcmp(instr, "ldrb") == 0 || strcmp(instr, "ldrsb") == 0){
			if(omit_amount){
				if(extended)
					sprintf(disassembled, "%s, %s]", disassembled, extend);
				else
					sprintf(disassembled, "%s]", disassembled);
			}
			else if(!omit_amount){
				if(extended)
					sprintf(disassembled, "%s, %s #%d]", disassembled, extend, amount);
				else
					sprintf(disassembled, "%s, lsl #0]", disassembled);
			}

			return disassembled;
		}
		else if(strcmp(instr, "str") == 0 || strcmp(instr, "ldr") == 0){
			if(_64bit)
				amount = S == 0 ? 0 : 3;
			else
				amount = S == 0 ? 0 : 2;
		}
		else if(strcmp(instr, "ldrsw") == 0)
			amount = S == 0 ? 0 : 2;
		
		if(extended){
			sprintf(disassembled, "%s, %s", disassembled, extend);
			
			if(amount != 0)
				sprintf(disassembled, "%s #%d]", disassembled, amount);
			else
				sprintf(disassembled, "%s]", disassembled);
		}
		else{
			if(amount != 0)
				sprintf(disassembled, "%s, lsl #%d]", disassembled, amount);
			else
				sprintf(disassembled, "%s]", disassembled);
		}

		return disassembled;
	}
	else if(V == 1){
		if(flt_amount == -1){
			if(omit_amount){
				if(extended)
					sprintf(disassembled, "%s, %s]", disassembled, extend);
				else
					sprintf(disassembled, "%s]", disassembled);
			}
			else if(!omit_amount){
				if(extended)
					sprintf(disassembled, "%s, %s #%d]", disassembled, extend, flt_amount);
				else
					sprintf(disassembled, "%s, lsl #0]", disassembled);
			}
		}
		else if(extended){
			sprintf(disassembled, "%s, %s", disassembled, extend);

			if(flt_amount != 0)
				sprintf(disassembled, "%s #%d]", disassembled, flt_amount);
			else
				sprintf(disassembled, "%s]", disassembled);
		}
		else if(!extended){
			if(flt_amount != 0)
				sprintf(disassembled, "%s, lsl #%d]", disassembled, flt_amount);
			else
				sprintf(disassembled, "%s]", disassembled);
		}

		return disassembled;
	}
	
	return disassembled;
}

char *DisassembleLoadAndStorePACInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int W = getbitsinrange(instruction->hex, 11, 1);
	unsigned int imm9 = getbitsinrange(instruction->hex, 12, 9);
	unsigned int S = getbitsinrange(instruction->hex, 22, 1);
	unsigned int M = getbitsinrange(instruction->hex, 23, 1);
	unsigned int V = getbitsinrange(instruction->hex, 26, 1);
	unsigned int size = getbitsinrange(instruction->hex, 30, 2);

	if(size != 3)
		return strdup(".undefined");

	int use_key_A = M == 0;
	unsigned int S10 = (S << 9) | imm9;
	
	S10 = sign_extend(S10, 10);
	S10 <<= 3;

	char *instr = malloc(8);
	sprintf(instr, "ldra");

	if(use_key_A)
		strcat(instr, "a");
	else
		strcat(instr, "b");

	const char *_Rt = ARM64_GeneralRegisters[Rt];
	const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, [%s, #%#x]%s", instr, _Rt, _Rn, S10, W == 1 ? "!" : "");
	
	return disassembled;
}

char *LoadsAndStoresDisassemble(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op0 = getbitsinrange(instruction->hex, 28, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 26, 1);
	unsigned int op2 = getbitsinrange(instruction->hex, 23, 2);
	unsigned int op3 = getbitsinrange(instruction->hex, 16, 6);
	unsigned int op4 = getbitsinrange(instruction->hex, 10, 2);

	
	//print_bin(op0, 4);
	//print_bin(op1, 1);
	//print_bin(op2, 2);
	//print_bin(op3, 6);
	//print_bin(op4, 2);

	//print_bin(op0 & 2, 1);
	//print_bin(op0 & 1, 1);
	
	//print_bin((op0 >> 1) & 1, 1);
	//print_bin(op0 & 1, 1);
	//print_bin(op2 >> 1, 1);

	if(((op0 & 1) == 0 && (op0 & 2) == 0 && (op0 & 8) == 0) && op1 == 1 && (op2 == 0 || op2 == 1) && (op3 >> 5) == 0)
		disassembled = DisassembleLoadStoreMultStructuresInstr(instruction, op2);
	else if((((op0 & 1) == 0 && (op0 & 2) == 0 && (op0 & 8) == 0) && op1 == 1 && (op2 == 2 || op2 == 3)))
		disassembled = DisassembleLoadStoreSingleStructuresInstr(instruction, op2 == 2 ? 0 : 1);
	else if(((op0 & 1) == 0 && (op0 & 2) == 0) && op1 == 0 && (op2 >> 1) == 0)
		disassembled = DisassembleLoadAndStoreExclusiveInstr(instruction);
	else if(((op0 & 2) == 0 && (op0 & 1) == 1) && (op2 >> 1) == 0)
		disassembled = DisassembleLoadAndStoreLiteralInstr(instruction);
	else if(((op0 & 2) == 2 && (op0 & 1) == 0) && (op2 >= 0 && op2 <= 3))
		disassembled = DisassembleLoadAndStoreRegisterPairInstr(instruction, op2);	
	else if((((op0 >> 1) & 1) == 1 && (op0 & 1) == 1) && (op2 >> 1) == 0 && (op3 >> 5) == 0 && (op4 >= 0 && op4 <= 3)){
		disassembled = DisassembleLoadAndStoreRegisterInstr(instruction, op4);
	}
	else if((((op0 >> 1) & 1) == 1 && (op0 & 1) == 1) && (op2 >> 1) == 0 && (op3 >> 5) == 1 && op4 == 0){
		disassembled = DisassembleAtomicMemoryInstr(instruction);
	}
	else if((((op0 >> 1) & 1) == 1 && (op0 & 1) == 1) && (op2 >> 1) == 0 && (op3 >> 5) == 1 && op4 == 2){
		disassembled = DisassembleLoadAndStoreRegisterOffsetInstr(instruction);
	}
	else if((((op0 >> 1) & 1) == 1 && (op0 & 1) == 1) && (op2 >> 1) == 0 && (op3 >> 5) == 1 && (op4 & 1) == 1){
		disassembled = DisassembleLoadAndStorePACInstr(instruction);
	}
	else if((((op0 >> 1) & 1) == 1 && (op0 & 1) == 1) && (op2 >> 1) == 1){
		disassembled = DisassembleLoadAndStoreRegisterInstr(instruction, UNSIGNED_IMMEDIATE);
	}
	else
		return strdup(".undefined");
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
