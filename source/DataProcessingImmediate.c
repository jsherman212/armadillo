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

	sprintf(disassembled, "%s %s, #%#lx", instr, ARM64_GeneralRegisters[rd], imm);

	return disassembled;
}

char *DisassembleAddSubtractImmediateInstr(unsigned int instruction){
	char *disassembled = NULL;

	unsigned int s = getbitsinrange(instruction, 29, 1);
	unsigned int op = getbitsinrange(instruction, 30, 1);
	unsigned int sf = getbitsinrange(instruction, 31, 1);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	unsigned int rd = getbitsinrange(instruction, 0, 5);
	unsigned int rn = getbitsinrange(instruction, 5, 5);
	unsigned long imm = getbitsinrange(instruction, 10, 12);
	unsigned int shift = getbitsinrange(instruction, 22, 2);
	
	if(sf == 0)
		imm = (unsigned int)imm;
	
	// in this case, an exception is thrown	
	if(shift == (1 << 1))
		return strdup(".unknown");
	
	// ADD (immediate)
	if(s == 0 && op == 0){
		disassembled = malloc(128);
		
		// mov to/from wsp/sp is used as an alias for add in this special case
		if(shift == 0 && imm == 0 && (rd == 0x1f || rn == 0x1f))
			sprintf(disassembled, "mov %s, %s", registers[rd], registers[rn]);
		else
			sprintf(disassembled, "add %s, %s, #%#lx%s", registers[rd], registers[rn], imm, shift == 1 ? ", lsl 12" : "");
	}
	// ADDS (immediate)
	else if(s == 1 && op == 0){
		disassembled = malloc(128);

		// cmn (immediate) is used as an alias in this case
		if(rd == 0x1f)
			sprintf(disassembled, "cmn %s, #%#lx%s", registers[rn], imm, shift == 1 ? ", lsl 12" : "");
		else
			sprintf(disassembled, "adds %s, %s, #%#lx%s", registers[rd], registers[rn], imm, shift == 1 ? ", lsl 12" : "");
	}
	// SUB (immediate)
	else if(s == 0 && op == 1){
		disassembled = malloc(128);
		sprintf(disassembled, "sub %s, %s, #%#lx%s", registers[rd], registers[rn], imm, shift == 1 ? ", lsl 12" : "");
	}
	// SUBS (immediate)
	else if(op == 1 && s == 1){
		disassembled = malloc(128);

		// cmp (immediate) is used as an alias in this case
		if(rd == 0x1f)
			sprintf(disassembled, "cmp %s, #%#lx%s", registers[rn], imm, shift == 1 ? ", lsl 12" : "");
		else
			sprintf(disassembled, "subs %s, %s, #%#lx%s", registers[rd], registers[rn], imm, shift == 1 ? ", lsl 12" : "");
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleLogicalImmediateInstr(unsigned int instruction){
	char *disassembled = NULL;

	unsigned int n = getbitsinrange(instruction, 22, 1);
	unsigned int opc = getbitsinrange(instruction, 29, 2);
	unsigned int sf = getbitsinrange(instruction, 31, 1);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	// unallocated
	if(sf == 0 && n == 1)
		return strdup(".unknown");
	
	unsigned int rd = getbitsinrange(instruction, 0, 5);
	unsigned int rn = getbitsinrange(instruction, 5, 5);
	unsigned int imms = getbitsinrange(instruction, 10, 6);
	unsigned int immr = getbitsinrange(instruction, 16, 6);	
	unsigned long imm;
	
	DecodeBitMasks(n, imms, immr, 1, &imm);
	
	if(imm == -1)
		return strdup(".unknown");
	
	// AND (immediate)
	if(opc == 0){
		disassembled = malloc(128);
		sprintf(disassembled, "and %s, %s, #%#lx", registers[rd], registers[rn], imm);
	}
	// ORR (immediate)
	else if(opc == 1){
		disassembled = malloc(128);

		// mov (bitmask immediate) is used in this case
		if(rn == 0x1f && !MoveWidePreferred(sf, n, imms, immr))
			sprintf(disassembled, "mov %s, #%#lx", registers[rd], imm);
		else
			sprintf(disassembled, "orr %s, %s, #%#lx", registers[rd], rn == 31 ? sf == 1 ? "xzr" : "wzr" : registers[rn], imm);
	}
	// EOR (immediate)
	else if(opc == (1 << 1)){
		disassembled = malloc(128);
		sprintf(disassembled, "eor %s, %s, #%#lx", registers[rd], registers[rn], imm);
	}
	// ANDS (immediate), when opc == 0b11
	else if(opc == 0x3){
		disassembled = malloc(128);

		// tst (immediate) is used in this case
		if(rd == 0x1f)
			sprintf(disassembled, "tst %s, #%#lx", registers[rn], imm);
		else
			sprintf(disassembled, "ands %s, %s, #%#lx", registers[rd], registers[rn], imm);
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
	// Logical (immediate)
	else if((op0 >> 1) == 1 && ((op1 >> 1) == 0))
		disassembled = DisassembleLogicalImmediateInstr(instruction);
	
	
	return disassembled;
}
