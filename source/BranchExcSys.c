#include <string.h>
#include "BranchExcSys.h"

char *decode_cond(unsigned int cond){
	unsigned int shifted = cond >> 1;
	char *decoded = malloc(8);

	// three because snprintf writes the NULL byte
	snprintf(decoded, 3, "%s", cond_table[shifted]);

	// the condition after the comma is used when this condition is met
	if((cond & 1) == 1 && cond != 0xf)
		sprintf(decoded, "%s", cond_table[shifted] + 3);

	return decoded;
}

char *DisassembleConditionalImmediateBranchInstr(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int o0 = getbitsinrange(instruction->hex, 4, 1);
	unsigned int o1 = getbitsinrange(instruction->hex, 24, 1);

	if(o0 == 0 && o1 == 0){
		disassembled = malloc(128);

		unsigned int cond = getbitsinrange(instruction->hex, 0, 4);
		unsigned int imm19 = getbitsinrange(instruction->hex, 5, 19);

		imm19 = sign_extend(imm19 << 2, 19);
		char *decoded_cond = decode_cond(cond);

		sprintf(disassembled, "b.%s #%#lx", decoded_cond, (signed int)imm19 + instruction->PC);

		free(decoded_cond);
	}
	else
		return strdup(".undefined");	

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleExcGenInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int ll = getbitsinrange(instruction->hex, 0, 2);
	unsigned int op2 = getbitsinrange(instruction->hex, 2, 3);
	unsigned int opc = getbitsinrange(instruction->hex, 21, 3);
	unsigned int imm16 = getbitsinrange(instruction->hex, 5, 16);
	
	// svc, hvc, or smc	
	if(opc == 0 && op2 == 0){
		disassembled = malloc(128);

		// ll == 0, nothing
		// ll == 1, svc
		// ll == 2, hvc
		// ll == 3, smc
		const char *table[] = { NULL, "svc", "hvc", "smc" };

		sprintf(disassembled, "%s #%#x", table[ll], imm16);
	}
	// brk or hlt
	else if((opc == 1 || opc == 2) && op2 == 0 && ll == 0){
		disassembled = malloc(128);
		
		// opc == 0, nothing
		// opc == 1, brk
		// opc == 2, hlt
		const char *table[] = { NULL, "brk", "hlt" };
		
		sprintf(disassembled, "%s #%#x", table[opc], imm16);
	}
	// dcps1, dcps2, or dcps3
	else if(opc == 5 && op2 == 0 && ll != 0){
		// no dcps4 and beyond
		if(ll > 3)
			return strdup(".undefined");

		disassembled = malloc(128);

		sprintf(disassembled, "dcps%d, #%#x", ll, imm16);
	}
	else
		return strdup(".undefined");


	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *BranchExcSysDisassemble(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int op2 = getbitsinrange(instruction->hex, 0, 5);
	unsigned int op1 = getbitsinrange(instruction->hex, 12, 14);
	unsigned int op0 = getbitsinrange(instruction->hex, 29, 3);

	//print_bin(op2, -1);
	//print_bin(op1, -1);
	//print_bin(op0, -1);

//	printf("op1 >> 14 = %d\n", (op1 >> 14) & 1);
	
	// Conditional branch (immediate)
	if(op0 == 0x2 && (op1 >> 13) == 0){
		//printf("b.cond\n");
		disassembled = DisassembleConditionalImmediateBranchInstr(instruction);
	}
	// Exception generation
	else if(op0 == 0x6 && (op1 >> 12) == 0){
		//printf("exception generation\n");
		disassembled = DisassembleExcGenInstr(instruction);
	}
	else
		return strdup(".undefined");



	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
