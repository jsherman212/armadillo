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

// caller must free return value
char *SysOp(unsigned int op1, unsigned int CRn, unsigned int CRm, unsigned int op2){
	char *ret = malloc(32);

	//print_bin(op1, 3);
	//print_bin(CRn, 4);
	//print_bin(CRm, 4);
	//print_bin(op2, 3);

	unsigned int result = op1 << 11;
	result |= (CRn << 7);
	result |= (CRm << 3);
	result |= op2;

	//print_bin(result, 14);

	switch(result){
	case 0x3c0:
		sprintf(ret, "Sys_AT,s1e1r");
		break;
	case 0x23c0:
		sprintf(ret, "Sys_AT,s1e2r");
		break;
	case 0x33c0:
		sprintf(ret, "Sys_AT,s1e3r");
		break;
	case 0x3c1:
		sprintf(ret, "Sys_AT,s1e1w");
		break;
	case 0x23c1:
		sprintf(ret, "Sys_AT,s1e2w");
		break;
	case 0x33c1:
		sprintf(ret, "Sys_AT,s1e3w");
		break;
	case 0x3c2:
		sprintf(ret, "Sys_AT,s1e0r");
		break;
	case 0x3c3:
		sprintf(ret, "Sys_AT,s1e0w");
		break;
	case 0x23c4:
		sprintf(ret, "Sys_AT,s12e1r");
		break;
	case 0x23c5:
		sprintf(ret, "Sys_AT,s12e1w");
		break;
	case 0x23c6:
		sprintf(ret, "Sys_AT,s12e0r");
		break;
	case 0x23c7:
		sprintf(ret, "Sys_AT,s12e0w");
		break;
	case 0x1ba1:
		sprintf(ret, "Sys_DC,zva");
		break;
	case 0x3b1:
		sprintf(ret, "Sys_DC,ivac");
		break;
	case 0x3b2:
		sprintf(ret, "Sys_DC,isw");
		break;
	case 0x1bd1:
		sprintf(ret, "Sys_DC,cvac");
		break;
	case 0x3d2:
		sprintf(ret, "Sys_DC,csw");
		break;
	case 0x1bd9:
		sprintf(ret, "Sys_DC,cvau");
		break;
	case 0x1bf1:
		sprintf(ret, "Sys_DC,civac");
		break;
	case 0x3f2:
		sprintf(ret, "Sys_DC,cisw");
		break;
	case 0x388:
		sprintf(ret, "Sys_IC,ialluis");
		break;
	case 0x3a8:
		sprintf(ret, "Sys_IC,iallu");
		break;
	case 0x1ba9:
		sprintf(ret, "Sys_IC,ivau");
		break;
	case 0x2401:
		sprintf(ret, "Sys_TLBI,ipas2e1is");
		break;
	case 0x2405:
		sprintf(ret, "Sys_TLBI,ipas2le1is");
		break;
	case 0x418:
		sprintf(ret, "Sys_TLBI,vmalle1is");
		break;
	case 0x2418:
		sprintf(ret, "Sys_TLBI,alle2is");
		break;
	case 0x3418:
		sprintf(ret, "Sys_TLBI,alle3is");
		break;
	case 0x419:
		sprintf(ret, "Sys_TLBI,vae1is");
		break;
	case 0x2419:
		sprintf(ret, "Sys_TLBI,vae2is");
		break;
	case 0x3419:
		sprintf(ret, "Sys_TLBI,vae3is");
		break;
	case 0x41a:
		sprintf(ret, "Sys_TLBI,aside1is");
		break;
	case 0x41b:
		sprintf(ret, "Sys_TLBI,vaae1is");
		break;
	case 0x241c:
		sprintf(ret, "Sys_TLBI,alle1is");
		break;
	case 0x41d:
		sprintf(ret, "Sys_TLBI,vale1is");
		break;
	case 0x241d:
		sprintf(ret, "Sys_TLBI,vale2is");
		break;
	case 0x341d:
		sprintf(ret, "Sys_TLBI,vale3is");
		break;
	case 0x241e:
		sprintf(ret, "Sys_TLBI,vmalls12e1is");
		break;
	case 0x41f:
		sprintf(ret, "Sys_TLBI,vaale1is");
		break;
	case 0x2421:
		sprintf(ret, "Sys_TLBI,ipas2e1");
		break;
	case 0x2425:
		sprintf(ret, "Sys_TLBI,ipas2le1");
		break;
	case 0x438:
		sprintf(ret, "Sys_TLBI,vmalle1");
		break;
	case 0x2438:
		sprintf(ret, "Sys_TLBI,alle2");
		break;
	case 0x3438:
		sprintf(ret, "Sys_TLBI,alle3");
		break;
	case 0x439:
		sprintf(ret, "Sys_TLBI,vae1");
		break;
	case 0x2439:
		sprintf(ret, "Sys_TLBI,vae2");
		break;
	case 0x3439:
		sprintf(ret, "Sys_TLBI,vae3");
		break;
	case 0x43a:
		sprintf(ret, "Sys_TLBI,aside1");
		break;
	case 0x43b:
		sprintf(ret, "Sys_TLBI,vaae1");
		break;
	case 0x243c:
		sprintf(ret, "Sys_TLBI,alle1");
		break;
	case 0x43d:
		sprintf(ret, "Sys_TLBI,vale1");
		break;
	case 0x243d:
		sprintf(ret, "Sys_TLBI,vale2");
		break;
	case 0x343d:
		sprintf(ret, "Sys_TLBI,vale3");
		break;
	case 0x243e:
		sprintf(ret, "Sys_TLBI,vmalls12e1");
		break;
	case 0x43f:
		sprintf(ret, "Sys_TLBI,vaale1");
		break;
	default:
		sprintf(ret, "Sys_SYS");
	}

	return ret;
}

char *DisassembleSystemInstruction(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int op2 = getbitsinrange(instruction->hex, 5, 3);
	unsigned int CRm = getbitsinrange(instruction->hex, 8, 4);
	unsigned int CRn = getbitsinrange(instruction->hex, 12, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 16, 3);
	unsigned int L = getbitsinrange(instruction->hex, 21, 1);
	
	// SYS
	if(L == 0){
		disassembled = malloc(128);
		char *op = SysOp(op1, CRn, CRm, op2);
		
		// aliases AT
		if(CRn == 0x7 && strcmp(op, "Sys_SYS") != 0){
			//printf("CRn == 0x7: op: %s\n", op);
			// AT
			if((CRm >> 1) == 0x4){
				//printf("op: %s\n", op);
				char *comma = strchr(op, ',');
					
				if(comma)
					sprintf(disassembled, "at %s, %s", comma + 1, ARM64_GeneralRegisters[Rt]);
				else
					sprintf(disassembled, ".unknown");
			}
			// DC or IC
			else{
				//printf("DC or IC\n");
				//printf("op: %s\n", op);
				char *comma = strchr(op, ',');

				if(comma){
					if(strstr(op, "IC")){
						//instr = "ic";
						
						sprintf(disassembled, "ic %s", comma + 1);

						if(Rt != 0x1f)
							sprintf(disassembled, "%s, %s", disassembled, ARM64_GeneralRegisters[Rt]);
					}
					else
						sprintf(disassembled, "dc %s, %s", comma + 1, ARM64_GeneralRegisters[Rt]);
				}
				else
					sprintf(disassembled, ".unknown");
			}
		}
		// TLBI
		else if(CRn == 0x8 && strcmp(op, "Sys_SYS") != 0){
			if(strcmp(op, "Sys_SYS") != 0){
				char *comma = strchr(op, ',');

				if(comma){
					sprintf(disassembled, "tlbi %s", comma + 1);

					if(Rt != 0x1f)
						sprintf(disassembled, "%s, %s", disassembled, ARM64_GeneralRegisters[Rt]);
				}
				else
					sprintf(disassembled, ".unknown");
			}
		}
		// Normal SYS instruction
		else
			sprintf(disassembled, "sys #%#x, C%d, C%d, #%#x, %s", op1, CRn, CRm, op2, ARM64_GeneralRegisters[Rt]);
		
		free(op);
	}
	// SYSL
	else if(L == 1){
		disassembled = malloc(128);
		sprintf(disassembled, "sysl %s, #%#x, C%d, C%d, #%#x", ARM64_GeneralRegisters[Rt], op1, CRn, CRm, op2);
	}
	else
		return strdup(".unknown");

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
	
	//print_bin((op1 << 28) >> 28, -1);
	//print_bin(op1 >> 12, -1);
	
	//print_bin(op1, 14);
	//print_bin((op1 << 27) >> 27, -1);

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
	else if(op0 == 0x6 && (op1 << 28) >> 28 == 0x4 && (op1 >> 7) == 0x20){
		printf("pstate\n");
		disassembled = DisassemblePSTATEInstr(instruction);
	}
	// System instructions
	else if(op0 == 0x6 && (op1 >> 10) == 0x4 && ((op1 >> 7) & 1) == 1){
		printf("system instruction\n");
		disassembled = DisassembleSystemInstruction(instruction);
	}
	else
		return strdup(".undefined");



	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}
