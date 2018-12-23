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
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}
