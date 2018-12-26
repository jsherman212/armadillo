#include "DataProcessingFloatingPoint.h"
#include <string.h>

char *DisassembleCryptographicAESInstr(struct instruction *instruction){
	char *disassembled = NULL;

	//printf("hi\n");

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);	
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 5);

	const char *_Rd = ARM64_VectorRegisters[Rd];
	const char *_Rn = ARM64_VectorRegisters[Rn];

	const char *instr_tbl[] = {NULL, NULL, NULL, NULL, "aese", "aesd", "aesmc", "aesimc"};
	
	if(opcode < 4 && opcode > (sizeof(instr_tbl) / sizeof(const char *)))
		return strdup(".undefined");
	
	const char *instr = instr_tbl[opcode];

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s.16b, %s.16b", instr, _Rd, _Rn);

	return disassembled;
}

char *DisassembleCryptographicThreeRegisterSHAInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);	
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 3);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);

	const char *instr_tbl[] = {"sha1c", "sha1p", "sha1m", "sha1su0", "sha256h", "sha256h2", "sha256su1"};
	
	if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
		return strdup(".undefined");

	const char *instr = instr_tbl[opcode];

	const char *_Rd = NULL, *_Rn = NULL;
	const char *_Rm = ARM64_VectorRegisters[Rm];

	int suffix_on_all = 0;

	// SHA1C, SHA1P, SHA1M
	if((opcode >= 0 && opcode <= 2)){
		_Rd = ARM64_VectorQRegisters[Rd];
		_Rn = ARM64_VectorSinglePrecisionRegisters[Rn];
	}
	// SHA1SU0, SHA256SU1
	else if(opcode == 3 || opcode == 6){
		_Rd = ARM64_VectorRegisters[Rd];
		_Rn = ARM64_VectorRegisters[Rn];

		suffix_on_all = 1;
	}
	// SHA256H, SHA256H2
	else{
		_Rd = ARM64_VectorQRegisters[Rd];
		_Rn = ARM64_VectorQRegisters[Rn];
	}

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s%s, %s%s, %s.4s", instr, _Rd, suffix_on_all ? ".4s" : "", _Rn, suffix_on_all ? ".4s" : "", _Rm);

	return disassembled;
}

char *DisassembleTwoRegisterSHAInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);	
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 5);

	const char *instr_tbl[] = {"sha1h", "sha1su1", "sha256su0"};

	if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
		return strdup(".undefined");

	const char *instr = instr_tbl[opcode];

	const char *_Rd = NULL, *_Rn = NULL;
	
	disassembled = malloc(128);
	bzero(disassembled, 128);

	if(strcmp(instr, "sha1h") == 0){
		_Rd = ARM64_VectorSinglePrecisionRegisters[Rd];
		_Rn = ARM64_VectorSinglePrecisionRegisters[Rn];

		sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);
	}
	else{
		_Rd = ARM64_VectorRegisters[Rd];
		_Rn = ARM64_VectorRegisters[Rn];

		sprintf(disassembled, "%s %s.4s, %s.4s", instr, _Rd, _Rn);
	}

	return disassembled;
}

char *DisassembleAdvancedSIMDScalarCopy(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);	
	unsigned int imm4 = getbitsinrange(instruction->hex, 11, 4);
	unsigned int imm5 = getbitsinrange(instruction->hex, 16, 5);
	unsigned int op = getbitsinrange(instruction->hex, 29, 1);

	//print_bin(imm5, 5);
	int size = LowestSetBit(imm5, 5);
	//printf("highest set bit: %d\n", size);

	if(size > 3)
		return strdup(".undefined");

	if(op == 0 && imm4 == 0){
		int index = imm5 >> (size + 1);
		//printf("index: %d\n", index);

		char T = '\0';
		char V = '\0';

		//print_bin(imm5, 5);
	
		if((imm5 & 1) == 1){
			T = 'b';
			V = 'b';
		}
		else if(((imm5 >> 1) & 1) == 1){
			T = 'h';
			V = 'h';
		}
		else if(((imm5 >> 2) & 1) == 1){
			T = 's';
			V = 's';
		}
		else if(((imm5 >> 3) & 1) == 1){
			T = 'd';
			V = 'd';
		}
		else
			return strdup(".undefined");
		
		disassembled = malloc(128);

		// the alias 'mov' is always preferred for scalar 'dup' instruction disassembly
		sprintf(disassembled, "mov %c%d, %s.%c[%d]", V, Rd, ARM64_VectorRegisters[Rn], T, index);


		return disassembled;
	}
	else
		return strdup(".undefined");
}

char *DataProcessingFloatingPointDisassemble(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op3 = getbitsinrange(instruction->hex, 10, 9);
	unsigned int op2 = getbitsinrange(instruction->hex, 19, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 23, 2);
	unsigned int op0 = getbitsinrange(instruction->hex, 28, 4);

	//printf("op0 %d\n", op0);
	//printf("op1 >> 1 %d\n", op1 >> 1);
	
	if(op0 == 4 && (op1 >> 1) == 0 && (op2 & ~0x8) == 5 && (((op3 >> 9) & 1) == 0 && ((op3 >> 8) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleCryptographicAESInstr(instruction);
	}
	else if(op0 == 5 && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 0 && (((op3 >> 5) & 1) == 0 && ((op3 >> 1) & 1) == 0 && (op3 & 1) == 0)){
		disassembled = DisassembleCryptographicThreeRegisterSHAInstr(instruction);
	}
	else if(op0 == 5 && (op1 >> 1) == 0 && (op2 & ~0x8) == 5 && (((op3 >> 9) & 1) == 0 && ((op3 >> 8) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleTwoRegisterSHAInstr(instruction);
	}
	else if((op0 & ~0x2) == 5 && op1 == 0 && (op2 >> 2) == 0 && (((op3 >> 5) & 1) == 0 && (op3 & 1) == 1)){
		disassembled = DisassembleAdvancedSIMDScalarCopy(instruction);
	}
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}
