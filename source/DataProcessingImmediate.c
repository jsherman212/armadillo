#include "DataProcessingImmediate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>



char *DisassemblePCRelativeAddressingInstr(unsigned int instruction){
	char *disassembled = NULL;

	unsigned int op = getbitsinrange(instruction, 31, 1);
	unsigned int rd = getbitsinrange(instruction, 0, 5);
	unsigned int immhi = getbitsinrange(instruction, 5, 19);
	unsigned int immlo = getbitsinrange(instruction, 29, 2);
	unsigned long imm = 0;

	if(op == 0){
		imm = (immhi << 2) | immlo;

		if(is_negative(imm, 21))
			imm = sign_extend2(imm, 21);
	}

	const char *instr = "adr";
	
	if(op == 1){
		// immhi: 18 bits
		// immlo: 2 bits
		// bottom 12 bits masked out adds 12 bits
		// 18 + 2 + 12 = 32, so no need to sign extend
		imm = ((immhi << 2) | immlo) << 12;
		instr = "adrp";
	}

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, %#lx", instr, ARM64_GeneralRegisters[rd], imm);

	return disassembled;
}

char *DisassembleAddSubtractImmediateInstr(unsigned int instruction){
	char *disassembled = NULL;

	unsigned int s = getbitsinrange(instruction, 29, 1);
	unsigned int op = getbitsinrange(instruction, 30, 1);
	unsigned int sf = getbitsinrange(instruction, 31, 1);

	printf("S: %d OP: %d SF: %d\n", s, op, sf);
	
	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	// ADD (immediate)
	if(s == 0 && op == 0){
		unsigned int rd = getbitsinrange(instruction, 0, 5);
		unsigned int rn = getbitsinrange(instruction, 5, 5);
		unsigned int shift = getbitsinrange(instruction, 22, 2);
		unsigned int imm = getbitsinrange(instruction, 10, 12);
		
		// in this case, an exception is thrown	
		if(shift == (1 << 1))
			return strdup(".unknown");

		if(sf == 1)
			imm = (unsigned long)imm;

		disassembled = malloc(128);
		
		// mov to/from wsp/sp is used as an alias for add in this special case
		if(shift == 0 && imm == 0 && (rd == 0x1f || rn == 0x1f))
			sprintf(disassembled, "mov %s, %s", registers[rd], registers[rn]);
		else{
			sprintf(disassembled, "add %s, %s, %#x", registers[rd], registers[rn], imm);
			
			if(shift == 1)
				sprintf(disassembled, "%s, lsl 12", disassembled);
		}
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DataProcessingImmediateDisassemble(unsigned int instruction){
	unsigned int op0 = getbitsinrange(instruction, 24, 3);
	unsigned int op1 = getbitsinrange(instruction, 22, 3);
	
	char *disassembled = NULL;

	// PC-rel. addressing
	// This is the only case where op0 is 0
	if(op0 == 0)
		disassembled = DisassemblePCRelativeAddressingInstr(instruction);
	// Add/subtract (immediate)
	else if(op0 == 1 && (op0 != (op0 & (1 << 1))))
		disassembled = DisassembleAddSubtractImmediateInstr(instruction);
	
	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
