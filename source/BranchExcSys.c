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

char *DisassembleHintInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op2 = getbitsinrange(instruction->hex, 5, 3);
	unsigned int CRm = getbitsinrange(instruction->hex, 8, 4);

	if(CRm == 0){
		disassembled = malloc(128);
		
		// out of xpacd, xpaci, and xpaclri, xpaclri is the only instruction that falls under system category
		const char *table[] = { "nop", "yield", "wfe", "wfi", "sev", "sevl", NULL, "xpaclri" };

		sprintf(disassembled, "%s", table[op2]);
	}
	else if(CRm == 1){
		disassembled = malloc(128);
		
		// op2 == 0, pacia1716 
		// op2 == 2, pacib1716
		// op2 == 4, autia1716
		// op2 == 6, autib1716
		const char *table[] = { "pacia1716", NULL, "pacib1716", NULL, "autia1716", NULL, "autib1716" };

		sprintf(disassembled, "%s", table[op2]);
	}
	else if(CRm == 2){
		disassembled = malloc(128);

		// op2 == 0, esb
		// op2 == 1, psb csync
		// op2 == 2, tsb csync
		// op2 == 4, csdb
		const char *table[] = { "esb", "psb csync", "tsb csync", NULL, "csdb" };

		sprintf(disassembled, "%s", table[op2]);
	}
	else if(CRm == 3){
		disassembled = malloc(128);
	
		// op2 == 0, paciaz
		// op2 == 1, paciasp
		// op2 == 2, pacibz
		// op2 == 3, pacibsp
		// op2 == 4, autiaz
		// op2 == 5, autiasp
		// op2 == 6, autibz
		// op2 == 7, autibsp
		const char *table[] = { "paciaz", "paciasp", "pacibz", "pacibsp", "autiaz", "autiasp", "autibz", "autibsp" };

		sprintf(disassembled, "%s", table[op2]);
	}
	// some kind of hint instruction?
	else{
		disassembled = malloc(128);

		sprintf(disassembled, "hint #%#x", (CRm << 4) | op2);
	}


	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleBarrierInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int op2 = getbitsinrange(instruction->hex, 5, 3);
	unsigned int CRm = getbitsinrange(instruction->hex, 8, 4);

	if(Rt == 0x1f){
		if(op2 == 2){
			disassembled = malloc(128);
			sprintf(disassembled, "clrex #%#x", CRm);
		}
		else if(op2 == 5 || (op2 == 4 && CRm != 0)){
			disassembled = malloc(128);
			
			const char *options[] = { "#0x0", "oshld", "oshst", "osh", "#0x4", "nshld", "nshst", "nsh", 
									"#0x8", "ishld", "ishst", "ish", "#0x12", "ld", "st", "sy" };

			const char *instr = op2 == 5 ? "dmb" : "dsb";

			sprintf(disassembled, "%s %s", instr, options[CRm]);
		}
		else if(op2 == 6){
			disassembled = malloc(128);

			if(CRm == 0xf)
				sprintf(disassembled, "isb sy");
			else
				sprintf(disassembled, "isb #%#x", CRm);
		}
		// SSBB and PSSBB
		else if(op2 == 4){
			if(CRm == 0){
				disassembled = malloc(128);
				sprintf(disassembled, "ssbb");
			}
			else if(CRm == 4){
				disassembled = malloc(128);
				sprintf(disassembled, "pssbb");
			}
		}
	}
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}

char *DisassemblePSTATEInstr(struct instruction *instruction){
	char *disassembled = NULL;

	printf("PSTATE\n");

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int op2 = getbitsinrange(instruction->hex, 5, 3);
	unsigned int CRm = getbitsinrange(instruction->hex, 8, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 16, 3);

	if(Rt == 0x1f){
		disassembled = malloc(128);
		
		if(op1 == 0 && op2 == 0)
			sprintf(disassembled, "cfinv");
		else{
			if(op1 == 0){
				const char *table[] = { NULL, NULL, NULL, "uao", "pan", "spsel" };
				sprintf(disassembled, "msr %s, #%#x", table[op2], CRm);
			}
			else{
				const char *table[] = { NULL, NULL, "dit", NULL, NULL, NULL, "daifset", "daifclr" };
				sprintf(disassembled, "msr %s, #%#x", table[op2], CRm);
			}
		}
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
	
	//printf("op0 %#x op1 %#x op2 %#x\n", op0, op1, op2);

	//print_bin(op2, -1);
	//print_bin(op1, -1);
	//print_bin(op0, -1);

//	printf("op1 >> 14 = %d\n", (op1 >> 14) & 1);
	
	print_bin(op1 >> 12, -1);
	print_bin(op1 >> 2, -1);

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
	// Hints
	else if(op0 == 0x6 && op1 == 0x1032 && op2 == 0x1f){
		//printf("Hint\n");
		disassembled = DisassembleHintInstr(instruction);
	}
	// Barriers
	else if(op0 == 0x6 && op1 == 0x1033){
		//printf("Barriers\n");
		disassembled = DisassembleBarrierInstr(instruction);
	}
	// PSTATE
	else if(op0 == 0x6 && ((op1 >> 12 == 1) && (((op1 >> 2) & 1) == 1))){
		printf("pstate\n");
		disassembled = DisassemblePSTATEInstr(instruction);
	}
	else
		return strdup(".undefined");



	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
