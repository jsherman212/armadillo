#include "DataProcessingImmediate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

char *DisassemblePCRelativeAddressingInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op = getbitsinrange(instruction->hex, 31, 1);
	unsigned int rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int immhi = getbitsinrange(instruction->hex, 5, 19);
	unsigned int immlo = getbitsinrange(instruction->hex, 29, 2);
	unsigned long imm = 0;

	if(op == 0){
		imm = (immhi << 2) | immlo;

		if(is_negative(imm, 21))
			imm = sign_extend2(imm, 21);

		imm += instruction->PC;
	}

	const char *instr = "adr";
	
	if(op == 1){
		// immhi: 18 bits
		// immlo: 2 bits
		// bottom 12 bits masked out adds 12 bits
		// 18 + 2 + 12 = 32, so no need to sign extend
		imm = ((immhi << 2) | immlo) << 12;
		
		// zero out bottom 12 bits of PC, then add it to the immediate
		imm += (instruction->PC & ~0xfff);
		
		instr = "adrp";
	}

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, #%#lx", instr, ARM64_GeneralRegisters[rd], imm);

	return disassembled;
}

char *DisassembleAddSubtractImmediateInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int s = getbitsinrange(instruction->hex, 29, 1);
	unsigned int op = getbitsinrange(instruction->hex, 30, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char **registers = ARM64_32BitGeneralRegisters;

	if(sf == 1)
		registers = ARM64_GeneralRegisters;

	unsigned int rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned long imm = getbitsinrange(instruction->hex, 10, 12);
	unsigned int shift = getbitsinrange(instruction->hex, 22, 2);
	
	if(sf == 0)
		imm = (unsigned int)imm;
	
	// these instructions can modify (w)sp
	const char *rd_reg = registers[rd];
	
	if(rd == 31)
		rd_reg = sf == 0 ? "wsp" : "sp";

	const char *rn_reg = registers[rn];

	if(rn == 31)
		rn_reg = sf == 0 ? "wsp" : "sp";

	// in this case, an exception is thrown	
	if(shift == (1 << 1))
		return strdup(".undefined");
	
	// ADD (immediate)
	if(s == 0 && op == 0){
		disassembled = malloc(128);
		
		// mov to/from wsp/sp is used as an alias for add in this special case
		if(shift == 0 && imm == 0 && (rd == 0x1f || rn == 0x1f))
			sprintf(disassembled, "mov %s, %s", rd_reg, rn_reg);
		else
			sprintf(disassembled, "add %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
	}
	// ADDS (immediate)
	else if(s == 1 && op == 0){
		disassembled = malloc(128);

		// cmn (immediate) is used as an alias in this case
		if(rd == 0x1f)
			sprintf(disassembled, "cmn %s, #%#lx%s", rn_reg, imm, shift == 1 ? ", lsl 12" : "");
		else
			sprintf(disassembled, "adds %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
	}
	// SUB (immediate)
	else if(s == 0 && op == 1){
		disassembled = malloc(128);
		sprintf(disassembled, "sub %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
	}
	// SUBS (immediate)
	else if(op == 1 && s == 1){
		disassembled = malloc(128);

		// cmp (immediate) is used as an alias in this case
		if(rd == 0x1f)
			sprintf(disassembled, "cmp %s, #%#lx%s", rn_reg, imm, shift == 1 ? ", lsl 12" : "");
		else
			sprintf(disassembled, "subs %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleLogicalImmediateInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int n = getbitsinrange(instruction->hex, 22, 1);
	unsigned int opc = getbitsinrange(instruction->hex, 29, 2);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char **registers = ARM64_GeneralRegisters;

	if(sf == 0)
		registers = ARM64_32BitGeneralRegisters;

	// unallocated
	if(sf == 0 && n == 1)
		return strdup(".undefined");
	
	unsigned int rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imms = getbitsinrange(instruction->hex, 10, 6); 
	unsigned int immr = getbitsinrange(instruction->hex, 16, 6);
	unsigned long imm;
	
	DecodeBitMasks(n, imms, immr, 1, &imm);
	
	if(imm == -1)
		return strdup(".undefined");
	
	// these instructions can modify (w)sp
	const char *rd_reg = registers[rd];
	
	if(rd == 31)
		rd_reg = sf == 0 ? "wsp" : "sp";

	const char *rn_reg = registers[rn];

	if(rn == 31)
		rn_reg = sf == 0 ? "wsp" : "sp";
	
	// AND (immediate)
	if(opc == 0){
		disassembled = malloc(128);
		sprintf(disassembled, "and %s, %s, #%#lx", rd_reg, rn_reg, imm);
	}
	// ORR (immediate)
	else if(opc == 1){
		disassembled = malloc(128);

		// mov (bitmask immediate) is used in this case
		if(rn == 0x1f && !MoveWidePreferred(sf, n, imms, immr))
			sprintf(disassembled, "mov %s, #%#lx", rd_reg, imm);
		else
			sprintf(disassembled, "orr %s, %s, #%#lx", rd_reg, registers[rn], imm);
	}
	// EOR (immediate)
	else if(opc == (1 << 1)){
		disassembled = malloc(128);
		sprintf(disassembled, "eor %s, %s, #%#lx", rd_reg, registers[rn], imm);
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

char *DisassembleMoveWideImmediateInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int hw = getbitsinrange(instruction->hex, 21, 2);
	unsigned int opc = getbitsinrange(instruction->hex, 29, 2);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);
	
	// unallocated
	if(opc == 1)
		return strdup(".undefined");
	
	// unallocated
	if(sf == 0 && (hw >> 1) == 1)
		return strdup(".undefined");

	const char **registers = ARM64_GeneralRegisters;

	if(sf == 0)
		registers = ARM64_32BitGeneralRegisters;

	unsigned int rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned long imm16 = getbitsinrange(instruction->hex, 5, 16);
	unsigned int shift = hw << 4;

	// MOVN
	if(opc == 0){
		disassembled = malloc(128);
		
		int usealias = 0;

		if(sf == 0)
			usealias = !(IsZero(imm16) && hw != 0) && !IsOnes(imm16, 16);
		else
			usealias = !(IsZero(imm16) && hw != 0);

		unsigned long result = ~(imm16 << shift);
		
		// mov (inverted wide immediate) is used in this case
		if(usealias)
			// if we are dealing with 32 bit, cut off the top 32 bits of result
			sprintf(disassembled, "mov %s, #%#lx", registers[rd], sf == 0 ? ((result << 32) >> 32) : result);
		else{
			sprintf(disassembled, "movn %s, #%#lx", registers[rd], imm16);

			if(shift != 0){
				char *lslstr = malloc(64);
				sprintf(lslstr, ", lsl #%d", shift);
				sprintf(disassembled, "%s%s", disassembled, lslstr);
				free(lslstr);
			}
		}
	}
	// MOVZ
	// opc == 0b10
	else if(opc == 0x2){
		disassembled = malloc(128);
		
		// mov (wide immediate) is used in this case
		if(!(IsZero(imm16) && hw != 0))
			sprintf(disassembled, "mov %s, #%#lx", registers[rd], imm16 << shift);
		else{
			sprintf(disassembled, "movz %s, #%#lx", registers[rd], imm16);
			
			if(shift != 0){
				char *lslstr = malloc(64);
				sprintf(lslstr, ", lsl #%d", shift);
				sprintf(disassembled, "%s%s", disassembled, lslstr);
				free(lslstr);
			}
		}
	}
	// MOVK
	// opc == 0b11
	else if(opc == 0x3){
		disassembled = malloc(128);

		sprintf(disassembled, "movk %s, #%#lx", registers[rd], imm16);

		if(shift != 0){
			char *lslstr = malloc(64);
			sprintf(lslstr, ", lsl #%d", shift);
			sprintf(disassembled, "%s%s", disassembled, lslstr);
			free(lslstr);
		}
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleBitfieldInstruction(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int n = getbitsinrange(instruction->hex, 22, 1);
	unsigned int opc = getbitsinrange(instruction->hex, 29, 2);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	// unallocated
	// opc == 0b11
	if(opc == 0x3)
		return strdup(".undefined");

	// unallocated
	if(sf == 0 && n == 1)
		return strdup(".undefined");

	// unallocated
	if(sf == 1 && n == 0)
		return strdup(".undefined");
	
	const char **registers = ARM64_GeneralRegisters;

	if(sf == 0)
		registers = ARM64_32BitGeneralRegisters;

	unsigned int rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imms = getbitsinrange(instruction->hex, 10, 6);
	unsigned int immr = getbitsinrange(instruction->hex, 16, 6);

	// undefined
	if(sf == 1 && n != 1)
		return strdup(".undefined");
	
	// undefined
	if(sf == 0 && (n != 0 || (immr & (1 << 5)) != 0 || (imms & (1 << 5)) != 0))
		return strdup(".undefined");

	int regsize = sf == 0 ? 32 : 64;
	
	// SBFM
	if(opc == 0){
		disassembled = malloc(128);
		
		// asr (immediate) is used in this case
		if((sf == 1 && imms == 0x3f) || (sf == 0 && imms == 0x1f))
			sprintf(disassembled, "asr %s, %s, #%#x", registers[rd], registers[rn], immr);
		// sbfiz is used in this case
		else if(imms < immr){
			sprintf(disassembled, "sbfiz %s, %s, #%#x, #%#x", registers[rd], registers[rn], regsize - immr, imms + 1);
		}
		// sbfx is used in this case
		else if(BFXPreferred(sf, (opc >> 1), imms, immr)){
			sprintf(disassembled, "sbfx %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms - immr + 1);
		}
		// sxtb, sxth, sxtw used in this case
		else if(immr == 0){
			// imms == 0x7
			const char *instr = "sxtb";

			if(imms == 0xf)
				instr = "sxth";
			else if(imms == 0x1f)
				instr = "sxtw";

			sprintf(disassembled, "%s %s, %s", instr, sf == 0 ? ARM64_32BitGeneralRegisters[rd] : ARM64_GeneralRegisters[rd], ARM64_32BitGeneralRegisters[rn]);
		}
		// normal sbfm
		else
			sprintf(disassembled, "sbfm %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms);
	}
	// BFM
	else if(opc == 1){
		disassembled = malloc(128);

		// bfc is used in this case
		if(imms < immr){
			immr = regsize - immr;
			imms += 1;
			
			// assume bfc
			const char *instr = "bfc";
			
			if(rd != 0x1f)
				instr = "bfi";
			
			sprintf(disassembled, "%s %s, %s, #%#x, #%#x", instr, registers[rd], registers[rn], immr, imms);
		}
		// bfxil is used in this case
		else if(imms >= immr)
			sprintf(disassembled, "bfxil %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms - immr + 1);
		// normal bfm
		else
			sprintf(disassembled, "bfm %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms);
	}
	// UBFM
	else if(opc == 0x2){
		disassembled = malloc(128);
		
		// lsl (immediate) is used in this case
		if(imms + 1 == immr){
			if((sf == 0 && imms != 0x1f) || (sf == 1 && imms != 0x3f))
				sprintf(disassembled, "lsl %s, %s, #%#x", registers[rd], registers[rn], -immr % regsize);
		}
		// lsr (immediate) is used in this case
		else if((sf == 0 && imms == 0x1f) || (sf == 1 && imms == 0x3f))
			sprintf(disassembled, "lsr %s, %s, #%#x", registers[rd], registers[rn], immr);
		// ubfiz is used in this case
		else if(imms < immr)
			sprintf(disassembled, "ubfiz %s, %s, #%#x, #%#x", registers[rd], registers[rn], regsize - immr, imms + 1);
		// ubfx is used in this case
		else if(BFXPreferred(sf, (opc >> 1), imms, immr))
			sprintf(disassembled, "ubfx %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms - immr + 1);
		// uxtb, uxth used in this case
		else if(immr == 0){
			// imms == 0x7
			const char *instr = "uxtb";

			if(imms == 0xf)
				instr = "uxth";

			sprintf(disassembled, "%s %s, %s", instr, ARM64_32BitGeneralRegisters[rd], ARM64_32BitGeneralRegisters[rn]);
		}
		// normal ubfm
		else
			sprintf(disassembled, "ubfm %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms);
	}

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DataProcessingImmediateDisassemble(struct instruction *instruction){
	unsigned int op0 = getbitsinrange(instruction->hex, 24, 2);
	unsigned int op1 = getbitsinrange(instruction->hex, 22, 2);
	
	char *disassembled = NULL;
	
	//print_bin(op0, -1);
	//print_bin(op1, -1);

	// PC-rel. addressing
	// This is the only case where op0 is 0
	if(op0 == 0)
		disassembled = DisassemblePCRelativeAddressingInstr(instruction);
	// Add/subtract (immediate)
	else if(op0 == 1 && (op1 >> 1) != 1){
		//printf("add/subtract\n");
		disassembled = DisassembleAddSubtractImmediateInstr(instruction);
	}
	// Logical (immediate)
	// op0 == 0b10
	else if(op0 == 0x2 && ((op1 >> 1) == 0)){
		//printf("logical\n");
		disassembled = DisassembleLogicalImmediateInstr(instruction);
	}
	// Move wide (immediate)
	else if((op0 >> 1) == 1 && ((op1 >> 1) == 1)){
		//printf("move wide\n");
		disassembled = DisassembleMoveWideImmediateInstr(instruction);
	}
	// Bitfield
	// op0 == 0b11
	else if(op0 == 0x3 && (op1 >> 1) == 0){
		//printf("Bitfield\n");

		disassembled = DisassembleBitfieldInstruction(instruction);
	
	}
	else{
		printf("Unknown\n");
	}

	//printf("DataProcessingImmediateDisassemble: ret = %p\n", disassembled);

	return disassembled;
}
