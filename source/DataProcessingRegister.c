#include "DataProcessingRegister.h"
#include <string.h>

char *DisassembleDataProcessingTwoSourceInstr(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 10, 6);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int S = getbitsinrange(instruction->hex, 29, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	// must be 64 bit in order to use PACGA
	if(opcode == 0xc && sf != 1)
		return strdup(".undefined");
	
	const char *instr_tbl[] = {NULL, NULL, "udiv", "sdiv", NULL, NULL, NULL, NULL, "lslv", "lsrv", "asrv", "rorv", 
								"pacga", NULL, NULL, NULL, "crc32b", "crc32h", "crc32w", "crc32x", "crc32cb",
								"crc32ch", "crc32cw", "crc32cx"};

	const char *instr = instr_tbl[opcode];
	
	if(!instr)
		return strdup(".undefined");

	const char *_Rd = registers[Rd];
	const char *_Rn = registers[Rn];
	const char *_Rm = NULL;

	if(strcmp(instr, "pacga") == 0)
		_Rm = Rm == 31 ? "sp" : ARM64_GeneralRegisters[Rm];
	else
		_Rm = registers[Rm];

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);
	
	return disassembled;
}

char *DisassembleDataProcessingOneSourceInstr(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 10, 6);
	unsigned int opcode2 = getbitsinrange(instruction->hex, 16, 5);
	unsigned int S = getbitsinrange(instruction->hex, 29, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	const char *_Rd = registers[Rd];
	const char *_Rn = NULL;

	if(opcode2 == 1 && opcode < 8)
		_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];
	else
		_Rn = registers[Rn];

	if(opcode2 == 0){
		const char *instr_tbl[] = {"rbit", "rev16", "rev", NULL, "clz", "cls"};
		const char *instr = instr_tbl[opcode];

		if(opcode == 2 && sf == 1)
			instr = "rev32";
		else if(opcode == 3 && sf == 1)
			instr = "rev";

		if(!instr)
			return strdup(".undefined");

		disassembled = malloc(128);
		sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);
	}
	else if(opcode2 == 1 && opcode < 8){
		const char *instr_tbl[] = {"pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"};
		const char *instr = instr_tbl[opcode];

		disassembled = malloc(128);
		sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);
	}
	else if(opcode2 == 1 && opcode >= 8 && Rn == 0x1f){
		// sub 8 to prevent an annoying row of NULL
		opcode -= 8;

		const char *instr_tbl[] = {"paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd"};
		const char *instr = instr_tbl[opcode];

		disassembled = malloc(128);
		sprintf(disassembled, "%s %s", instr, _Rd);
	}

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}

const char *decode_shift(unsigned int op){
	switch(op){
	case 0:
		return "lsl";
	case 1:
		return "lsr";
	case 2:
		return "asr";
	case 3:
		return "ror";
	default:
		return NULL;
	};
}

char *DisassembleLogicalShiftedRegisterInstr(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imm6 = getbitsinrange(instruction->hex, 10, 6);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int N = getbitsinrange(instruction->hex, 21, 1);
	unsigned int shift = getbitsinrange(instruction->hex, 22, 2);
	unsigned int opc = getbitsinrange(instruction->hex, 29, 2);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);
	
	if(sf == 0 && (imm6 >> 5) == 1)
		return strdup(".undefined");

	const char **registers = ARM64_32BitGeneralRegisters;	

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	unsigned int encoding = (sf << 3) | (opc << 1) | N;
	
	const char *instr_tbl[] = {"and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"};
	const char *instr = NULL;

	if(sf == 0)
		instr = instr_tbl[encoding];
	else
		instr = instr_tbl[encoding - 8];

	const char *_Rd = registers[Rd];
	const char *_Rn = registers[Rn];
	const char *_Rm = registers[Rm];
	
	const char *_shift = decode_shift(shift);

	disassembled = malloc(128);
	bzero(disassembled, 128);

	if(strcmp(instr, "orr") == 0 && shift == 0 && imm6 == 0 && Rn == 0x1f){
		sprintf(disassembled, "mov %s, %s", _Rd, _Rm);
	}
	else if(strcmp(instr, "orn") == 0 && Rn == 0x1f){
		sprintf(disassembled, "mvn %s, %s", _Rd, _Rm);

		if(shift != 0)
			sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
	}
	else if(strcmp(instr, "ands") == 0 && Rd == 0x1f){
		sprintf(disassembled, "tst %s, %s", _Rn, _Rm);

		if(shift != 0)
			sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
	}
	else{
		sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

		if(shift != 0)
			sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleAddSubtractShiftedOrExtendedInstr(struct instruction *instruction, int kind){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imm3 = getbitsinrange(instruction->hex, 10, 3);
	unsigned int option = getbitsinrange(instruction->hex, 13, 3);
	unsigned int imm6 = (option << 3) | imm3;
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int shift = getbitsinrange(instruction->hex, 22, 2);
	unsigned int opt = shift;
	unsigned int S = getbitsinrange(instruction->hex, 29, 1);
	unsigned int op = getbitsinrange(instruction->hex, 30, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	if(kind == SHIFTED && shift == 3)
		return strdup(".undefined");

	unsigned int encoding = (sf << 2) | (op << 1) | S;

	const char *instr_tbl[] = {"add", "adds", "sub", "subs"};
	const char *instr = NULL;

	if(sf == 0)
		instr = instr_tbl[encoding];
	else
		instr = instr_tbl[encoding - 4];

	printf("instr: %s\n", instr);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	const char *_Rd = registers[Rd];
	const char *_Rn = registers[Rn];
	const char *_Rm = registers[Rm];

	const char *_shift = decode_shift(shift);

	if(kind == EXTENDED){
		if(strcmp(instr, "add") == 0 || strcmp(instr, "sub") == 0){
			if(sf == 0){
				_Rd = Rd == 31 ? "wsp" : registers[Rd];
				_Rn = Rn == 31 ? "wsp" : registers[Rn];
			}
			else{
				_Rd = Rd == 31 ? "sp" : registers[Rd];
				_Rn = Rn == 31 ? "sp" : registers[Rn];
			}
		}
		else if(strcmp(instr, "adds") == 0 || strcmp(instr, "subs") == 0){
			if(sf == 0)
				_Rn = Rn == 31 ? "wsp" : registers[Rn];
			else
				_Rn = Rn == 31 ? "sp" : registers[Rn];
		}
	}

	disassembled = malloc(128);
	bzero(disassembled, 128);

	if(kind == SHIFTED){
		if(strcmp(instr, "adds") == 0 && Rd == 0x1f){
			sprintf(disassembled, "cmn %s, %s", _Rn, _Rm);

			if(imm6 != 0)
				sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
		}
		else if(strcmp(instr, "sub") == 0 && Rn == 0x1f){
			sprintf(disassembled, "neg %s, %s", _Rd, _Rm);

			if(imm6 != 0)
				sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
		}
		else if(strcmp(instr, "subs") == 0 && (Rd == 0x1f || Rn == 0x1f)){
			if(Rd == 0x1f){
				sprintf(disassembled, "cmp %s, %s", _Rn, _Rm);

				if(imm6 != 0)
					sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
			}
			else if(Rn == 0x1f){
				sprintf(disassembled, "negs %s, %s", _Rd, _Rm);

				if(imm6 != 0)
					sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
			}
		}
		else{
			sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

			if(imm6 != 0)
				sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
		}
	}


	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}

char *DataProcessingRegisterDisassemble(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op3 = getbitsinrange(instruction->hex, 10, 6);
	unsigned int op2 = getbitsinrange(instruction->hex, 21, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 28, 1);
	unsigned int op0 = getbitsinrange(instruction->hex, 30, 1);

	printf("DisassembleDataProcessingRegister\n");

	if(op0 == 0 && op1 == 1 && op2 == 6){
		disassembled = DisassembleDataProcessingTwoSourceInstr(instruction);
	}
	else if(op0 == 1 && op1 == 1 && op2 == 6){
		disassembled = DisassembleDataProcessingOneSourceInstr(instruction);
	}
	else if((op2 >> 3) == 0 && op1 == 0){
		disassembled = DisassembleLogicalShiftedRegisterInstr(instruction);
	}
	else if((op2 & 8) == 8 && ((op2 & 1) == 1 || (op2 & 1) == 0) && op1 == 0){
		disassembled = DisassembleAddSubtractShiftedOrExtendedInstr(instruction, (op2 & 1));
	}
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}
