#include "BranchExcSys.h"

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
	
	if(opc == 0 && op2 == 0){
		disassembled = malloc(128);
		const char *table[] = { NULL, "svc", "hvc", "smc" };
		if(!check_bounds(ll, ARRAY_SIZE(table)))
			return strdup(".undefined");

		sprintf(disassembled, "%s #%#x", table[ll], imm16);
	}
	else if((opc == 1 || opc == 2) && op2 == 0 && ll == 0){
		disassembled = malloc(128);
		const char *table[] = { NULL, "brk", "hlt" };
		if(!check_bounds(ll, ARRAY_SIZE(table)))
			return strdup(".undefined");
		
		sprintf(disassembled, "%s #%#x", table[opc], imm16);
	}
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
		const char *table[] = { "nop", "yield", "wfe", "wfi", "sev", "sevl", NULL, "xpaclri" };
		if(!check_bounds(op2, ARRAY_SIZE(table)))
			return strdup(".undefined");

		sprintf(disassembled, "%s", table[op2]);
	}
	else if(CRm == 1){
		disassembled = malloc(128);
		const char *table[] = { "pacia1716", NULL, "pacib1716", NULL, "autia1716", NULL, "autib1716" };
		if(!check_bounds(op2, ARRAY_SIZE(table)))
			return strdup(".undefined");

		sprintf(disassembled, "%s", table[op2]);
	}
	else if(CRm == 2){
		disassembled = malloc(128);
		const char *table[] = { "esb", "psb csync", "tsb csync", NULL, "csdb" };
		if(!check_bounds(op2, ARRAY_SIZE(table)))
			return strdup(".undefined");

		sprintf(disassembled, "%s", table[op2]);
	}
	else if(CRm == 3){
		disassembled = malloc(128);
		const char *table[] = { "paciaz", "paciasp", "pacibz", "pacibsp", "autiaz", "autiasp", "autibz", "autibsp" };
		if(!check_bounds(op2, ARRAY_SIZE(table)))
			return strdup(".undefined");

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

			if(!check_bounds(CRm, ARRAY_SIZE(options)))
				return strdup(".undefined");
			
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

	unsigned int result = op1 << 11;
	result |= (CRn << 7);
	result |= (CRm << 3);
	result |= op2;

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

char *DisassembleSystemInstr(struct instruction *instruction){
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

const char *GetSysReg(unsigned int op0, unsigned int CRn, unsigned int op1, unsigned int op2, unsigned int CRm){
	unsigned int systemreg = op0 << 14;
	systemreg |= (CRn << 10);
	systemreg |= (op1 << 7);
	systemreg |= (op2 << 4);
	systemreg |= CRm;

	switch(systemreg){
	case 0xc410:
		return "ACTLR_EL1";
	case 0xc610:
		return "ACTLR_EL2";
	case 0xc710:
		return "ACTLR_EL3";
	case 0xd401:
		return "AFSR0_EL1";
	case 0xd681:
		return "AFSR0_EL12";
	case 0xd601:
		return "AFSR0_EL2";
	case 0xd701:
		return "AFSR0_EL3";
	case 0xd411:
		return "AFSR1_EL1";
	case 0xd691:
		return "AFSR1_EL12";
	case 0xd611:
		return "AFSR1_EL2";
	case 0xd711:
		return "AFSR1_EL3";
	case 0xc0f0:
		return "AIDR_EL1";
	case 0xe803:
		return "AMAIR_EL1";
	case 0xea83:
		return "AMAIR_EL12";
	case 0xea03:
		return "AMAIR_EL2";
	case 0xeb03:
		return "AMAIR_EL3";
	case 0xf592:
		return "AMCFGR_EL0";
	case 0xf5a2:
		return "AMCGCR_EL0";
	case 0xf5c2:
		return "AMCNTENCLR0_EL0";
	case 0xf583:
		return "AMCNTENCLR1_EL0";
	case 0xf5d2:
		return "AMCNTENSET0_EL0";
	case 0xf593:
		return "AMCNTENSET1_EL0";
	case 0xf582:
		return "AMCR_EL0";
	case 0xf5b2:
		return "AMUSERENR_EL0";
	case 0x2c12:
		return "APDAKeyHi_EL1";
	case 0x2c02:
		return "APDAKeyLo_EL1";
	case 0x2c32:
		return "APDBKeyHi_EL1";
	case 0x2c22:
		return "APDBKeyLo_EL1";
	case 0x2c13:
		return "APGAKeyHi_EL1";
	case 0x2c03:
		return "APGAKeyLo_EL1";
	case 0x2c11:
		return "APIAKeyHi_EL1";
	case 0x2c01:
		return "APIAKeyLo_EL1";
	case 0x2c31:
		return "APIBKeyHi_EL1";
	case 0x2c21:
		return "APIBKeyLo_EL1";
	case 0xca0:
		return "CCSIDR2_EL1";
	case 0xc080:
		return "CCSIDR_EL1";
	case 0xc090:
		return "CLIDR_EL1";
	case 0xf980:
		return "CNTFRQ_EL0";
	case 0xfa01:
		return "CNTHCTL_EL2";
	case 0xfa15:
		return "CNTHPS_CTL_EL2";
	case 0xfa25:
		return "CNTHPS_CVAL_EL2";
	case 0xfa05:
		return "CNTHPS_TVAL_EL2";
	case 0xfa12:
		return "CNTHP_CTL_EL2";
	case 0xfa22:
		return "CNTHP_CVAL_EL2";
	case 0xfa02:
		return "CNTHP_TVAL_EL2";
	case 0xfa14:
		return "CNTHVS_CTL_EL2";
	case 0xfa24:
		return "CNTHVS_CVAL_EL2";
	case 0xfa04:
		return "CNTHVS_TVAL_EL2";
	case 0xee13:
		return "CNTHV_CTL_EL2";
	case 0xee23:
		return "CNTHV_CVAL_EL2";
	case 0xee03:
		return "CNTHV_TVAL_EL2";
	case 0xf801:
		return "CNTKCTL_EL1";
	case 0xfa81:
		return "CNTKCTL_EL12";
	case 0xf990:
		return "CNTPCT_EL0";
	case 0xfb92:
		return "CNTPS_CTL_EL1";
	case 0xfba2:
		return "CNTPS_CVAL_EL1";
	case 0xfb82:
		return "CNTPS_TVAL_EL1";
	case 0xf992:
		return "CNTP_CTL_EL0";
	case 0xfa92:
		return "CNTP_CTL_EL02";
	case 0xf9a2:
		return "CNTP_CVAL_EL0";
	case 0xfaa2:
		return "CNTP_CVAL_EL02";
	case 0xf982:
		return "CNTP_TVAL_EL0";
	case 0xfa82:
		return "CNTP_TVAL_EL02";
	case 0xf9a0:
		return "CNTVCT_EL0";
	case 0xfa30:
		return "CNTVOFF_EL2";
	case 0xed93:
		return "CNTV_CTL_EL0";
	case 0xf993:
		return "CNTV_CTL_EL0";
	case 0xfa93:
		return "CNTV_CTL_EL02";
	case 0xeda3:
		return "CNTV_CVAL_EL0";
	case 0xf9a3:
		return "CNTV_CVAL_EL0";
	case 0xfaa3:
		return "CNTV_CVAL_EL02";
	case 0xed83:
		return "CNTV_TVAL_EL0";
	case 0xf983:
		return "CNTV_TVAL_EL0";
	case 0xfa83:
		return "CNTV_TVAL_EL02";
	case 0xdc10:
		return "CONTEXTIDR_EL1";
	case 0xf410:
		return "CONTEXTIDR_EL1";
	case 0xf690:
		return "CONTEXTIDR_EL12";
	case 0xde10:
		return "CONTEXTIDR_EL2";
	case 0xc420:
		return "CPACR_EL1";
	case 0xc6a0:
		return "CPACR_EL12";
	case 0xc621:
		return "CPTR_EL2";
	case 0xc721:
		return "CPTR_EL3";
	case 0xc100:
		return "CSSELR_EL1";
	case 0xc190:
		return "CTR_EL0";
	case 0xd022:
		return "CurrentEL";
	case 0xce00:
		return "DACR32_EL2";
	case 0xd192:
		return "DAIF";
	case 0x9c6e:
		return "DBGAUTHSTATUS_EL1";
	case 0x9c69:
		return "DBGCLAIMCLR_EL1";
	case 0x9c68:
		return "DBGCLAIMSET_EL1";
	case 0x8185:
		return "DBGDTRRX_EL0";
	case 0x8184:
		return "DBGDTR_EL0";
	case 0x8444:
		return "DBGPRCR_EL1";
	case 0x8207:
		return "DBGVCR32_EL2";
	case 0xc1f0:
		return "DCZID_EL0";
	case 0xf011:
		return "DISR_EL1";
	case 0x4dd2:
		return "DIT";
	case 0xda29:
		return "DLR_EL0";
	case 0xd185:
		return "DSPSR_EL0";
	case 0xd010:
		return "ELR_EL1";
	case 0xd290:
		return "ELR_EL12";
	case 0xd210:
		return "ELR_EL2";
	case 0xd310:
		return "ELR_EL3";
	case 0xd403:
		return "ERRIDR_EL1";
	case 0xd413:
		return "ERRSELR_EL1";
	case 0xd434:
		return "ERXADDR_EL1";
	case 0xd414:
		return "ERXCTLR_EL1";
	case 0xd404:
		return "ERXFR_EL1";
	case 0xd405:
		return "ERXMISC0_EL1";
	case 0xd415:
		return "ERXMISC1_EL1";
	case 0xd425:
		return "ERXMISC2_EL1";
	case 0xd435:
		return "ERXMISC3_EL1";
	case 0xd464:
		return "ERXPFGCDN_EL1";
	case 0xd454:
		return "ERXPFGCTL_EL1";
	case 0xd444:
		return "ERXPFGF_EL1";
	case 0xd424:
		return "ERXSTATUS_EL1";
	case 0xd402:
		return "ESR_EL1";
	case 0xd682:
		return "ESR_EL12";
	case 0xd602:
		return "ESR_EL2";
	case 0xd702:
		return "ESR_EL3";
	case 0xd800:
		return "FAR_EL1";
	case 0xda80:
		return "FAR_EL12";
	case 0xda00:
		return "FAR_EL2";
	case 0xdb00:
		return "FAR_EL3";
	case 0xd184:
		return "FPCR";
	case 0xd603:
		return "FPEXC32_EL2";
	case 0xd194:
		return "FPSR";
	case 0xc671:
		return "HACR_EL2";
	case 0xc601:
		return "HCR_EL2";
	case 0xda40:
		return "HPFAR_EL2";
	case 0xc631:
		return "HSTR_EL2";
	case 0xc045:
		return "ID_AA64AFR0_EL1";
	case 0xc055:
		return "ID_AA64AFR1_EL1";
	case 0xc005:
		return "ID_AA64DFR0_EL1";
	case 0xc015:
		return "ID_AA64DFR1_EL1";
	case 0xc006:
		return "ID_AA64ISAR0_EL1";
	case 0xc016:
		return "ID_AA64ISAR1_EL1";
	case 0xc007:
		return "ID_AA64MMFR0_EL1";
	case 0xc017:
		return "ID_AA64MMFR1_EL1";
	case 0xc27:
		return "ID_AA64MMFR2_EL1";
	case 0xc004:
		return "ID_AA64PFR0_EL1";
	case 0xc014:
		return "ID_AA64PFR1_EL1";
	case 0xc031:
		return "ID_AFR0_EL1";
	case 0xc021:
		return "ID_DFR0_EL1";
	case 0xc002:
		return "ID_ISAR0_EL1";
	case 0xc012:
		return "ID_ISAR1_EL1";
	case 0xc022:
		return "ID_ISAR2_EL1";
	case 0xc032:
		return "ID_ISAR3_EL1";
	case 0xc042:
		return "ID_ISAR4_EL1";
	case 0xc052:
		return "ID_ISAR5_EL1";
	case 0xc72:
		return "ID_ISAR6_EL1";
	case 0xc041:
		return "ID_MMFR0_EL1";
	case 0xc051:
		return "ID_MMFR1_EL1";
	case 0xc061:
		return "ID_MMFR2_EL1";
	case 0xc071:
		return "ID_MMFR3_EL1";
	case 0xc062:
		return "ID_MMFR4_EL1";
	case 0xc001:
		return "ID_PFR0_EL1";
	case 0xc011:
		return "ID_PFR1_EL1";
	case 0xc043:
		return "ID_PFR2_EL1";
	case 0xd610:
		return "IFSR32_EL2";
	case 0xf001:
		return "ISR_EL1";
	case 0xac34:
		return "LORC_EL1";
	case 0xac14:
		return "LOREA_EL1";
	case 0xac74:
		return "LORID_EL1";
	case 0xac24:
		return "LORN_EL1";
	case 0xac04:
		return "LORSA_EL1";
	case 0xe802:
		return "MAIR_EL1";
	case 0xea82:
		return "MAIR_EL12";
	case 0xea02:
		return "MAIR_EL2";
	case 0xeb02:
		return "MAIR_EL3";
	case 0x8002:
		return "MDCCINT_EL1";
	case 0x8181:
		return "MDCCSR_EL0";
	case 0xc611:
		return "MDCR_EL2";
	case 0xc713:
		return "MDCR_EL3";
	case 0x8400:
		return "MDRAR_EL1";
	case 0x8022:
		return "MDSCR_EL1";
	case 0xc000:
		return "MIDR_EL1";
	case 0xc050:
		return "MPIDR_EL1";
	case 0xc003:
		return "MVFR0_EL1";
	case 0xc013:
		return "MVFR1_EL1";
	case 0xc023:
		return "MVFR2_EL1";
	case 0xd182:
		return "NZCV";
	case 0x8443:
		return "OSDLR_EL1";
	case 0x8020:
		return "OSDTRRX_EL1";
	case 0x8023:
		return "OSDTRTX_EL1";
	case 0x8026:
		return "OSECCR_EL1";
	case 0x8440:
		return "OSLAR_EL1";
	case 0x8441:
		return "OSLSR_EL1";
	case 0x4c32:
		return "PAN";
	case 0xdc04:
		return "PAR_EL1";
	case 0xe47a:
		return "PMBIDR_EL1";
	case 0xe40a:
		return "PMBLIMITR_EL1";
	case 0xe41a:
		return "PMBPTR_EL1";
	case 0xe43a:
		return "PMBSR_EL1";
	case 0xf9ff:
		return "PMCCFILTR_EL0";
	case 0xe58d:
		return "PMCCNTR_EL0";
	case 0xe5ec:
		return "PMCEID0_EL0";
	case 0xe5fc:
		return "PMCEID1_EL0";
	case 0xe5ac:
		return "PMCNTENCLR_EL0";
	case 0xe59c:
		return "PMCNTENSET_EL0";
	case 0xe58c:
		return "PMCR_EL0";
	case 0xe42e:
		return "PMINTENCLR_EL1";
	case 0xe41e:
		return "PMINTENSET_EL1";
	case 0xe46e:
		return "PMMIR_EL1";
	case 0xe5bc:
		return "PMOVSCLR_EL0";
	case 0xe5be:
		return "PMOVSSET_EL0";
	case 0xe409:
		return "PMSCR_EL1";
	case 0xe689:
		return "PMSCR_EL12";
	case 0xe609:
		return "PMSCR_EL2";
	case 0xe5dc:
		return "PMSELR_EL0";
	case 0xe459:
		return "PMSEVFR_EL1";
	case 0xe449:
		return "PMSFCR_EL1";
	case 0xe429:
		return "PMSICR_EL1";
	case 0xe479:
		return "PMSIDR_EL1";
	case 0xe439:
		return "PMSIRR_EL1";
	case 0xe469:
		return "PMSLATFR_EL1";
	case 0xe5cc:
		return "PMSWINC_EL0";
	case 0xe58e:
		return "PMUSERENR_EL0";
	case 0xe5ad:
		return "PMXEVCNTR_EL0";
	case 0xe59d:
		return "PMXEVTYPER_EL0";
	case 0xc060:
		return "REVIDR_EL1";
	case 0xf020:
		return "RMR_EL1";
	case 0xf220:
		return "RMR_EL2";
	case 0xf320:
		return "RMR_EL3";
	case 0xf010:
		return "RVBAR_EL1";
	case 0xf210:
		return "RVBAR_EL2";
	case 0xf310:
		return "RVBAR_EL3";
	case 0xc701:
		return "SCR_EL3";
	case 0xc400:
		return "SCTLR_EL1";
	case 0xc680:
		return "SCTLR_EL12";
	case 0xc600:
		return "SCTLR_EL2";
	case 0xc700:
		return "SCTLR_EL3";
	case 0xc613:
		return "SDER32_EL2";
	case 0xc711:
		return "SDER_EL3";
	case 0xd000:
		return "SPSR_EL1";
	case 0xd280:
		return "SPSR_EL12";
	case 0xd200:
		return "SPSR_EL2";
	case 0xd300:
		return "SPSR_EL3";
	case 0xd213:
		return "SPSR_abt";
	case 0xd233:
		return "SPSR_fiq";
	case 0xd203:
		return "SPSR_irq";
	case 0xd223:
		return "SPSR_und";
	case 0xd002:
		return "SPSel";
	case 0xd001:
		return "SP_EL0";
	case 0xd201:
		return "SP_EL1";
	case 0xd301:
		return "SP_EL2";
	case 0xc820:
		return "TCR_EL1";
	case 0xcaa0:
		return "TCR_EL12";
	case 0xca20:
		return "TCR_EL2";
	case 0xcb20:
		return "TCR_EL3";
	case 0xf5b0:
		return "TPIDRRO_EL0";
	case 0xf5a0:
		return "TPIDR_EL0";
	case 0xf440:
		return "TPIDR_EL1";
	case 0xf620:
		return "TPIDR_EL2";
	case 0xf720:
		return "TPIDR_EL3";
	case 0x1c12:
		return "TRFCR_EL1";
	case 0x1e92:
		return "TRFCR_EL12";
	case 0x1e12:
		return "TRFCR_EL2";
	case 0xc800:
		return "TTBR0_EL1";
	case 0xca80:
		return "TTBR0_EL12";
	case 0xca00:
		return "TTBR0_EL2";
	case 0xcb00:
		return "TTBR0_EL3";
	case 0x2c10:
		return "TTBR1_EL1";
	case 0xc810:
		return "TTBR1_EL1";
	case 0xca90:
		return "TTBR1_EL12";
	case 0x2e10:
		return "TTBR1_EL2";
	case 0x4c42:
		return "UAO";
	case 0xf000:
		return "VBAR_EL1";
	case 0xf280:
		return "VBAR_EL12";
	case 0xf200:
		return "VBAR_EL2";
	case 0xf300:
		return "VBAR_EL3";
	case 0xf211:
		return "VDISR_EL2";
	case 0xc250:
		return "VMPIDR_EL2";
	case 0xca02:
		return "VNCR_EL2";
	case 0xc200:
		return "VPIDR_EL2";
	case 0xd632:
		return "VSESR_EL2";
	case 0xca26:
		return "VSTCR_EL2";
	case 0xca06:
		return "VSTTBR_EL2";
	case 0xca21:
		return "VTCR_EL2";
	case 0xca01:
		return "VTTBR_EL2";
	case 0xed88:
		return "PMEVCNTR0_EL0";
	case 0xed98:
		return "PMEVCNTR1_EL0";
	case 0xeda8:
		return "PMEVCNTR2_EL0";
	case 0xedb8:
		return "PMEVCNTR3_EL0";
	case 0xedc8:
		return "PMEVCNTR4_EL0";
	case 0xedd8:
		return "PMEVCNTR5_EL0";
	case 0xede8:
		return "PMEVCNTR6_EL0";
	case 0xedf8:
		return "PMEVCNTR7_EL0";
	case 0xed89:
		return "PMEVCNTR8_EL0";
	case 0xed99:
		return "PMEVCNTR9_EL0";
	case 0xeda9:
		return "PMEVCNTR10_EL0";
	case 0xedb9:
		return "PMEVCNTR11_EL0";
	case 0xedc9:
		return "PMEVCNTR12_EL0";
	case 0xedd9:
		return "PMEVCNTR13_EL0";
	case 0xede9:
		return "PMEVCNTR14_EL0";
	case 0xedf9:
		return "PMEVCNTR15_EL0";
	case 0xed8a:
		return "PMEVCNTR16_EL0";
	case 0xed9a:
		return "PMEVCNTR17_EL0";
	case 0xedaa:
		return "PMEVCNTR18_EL0";
	case 0xedba:
		return "PMEVCNTR19_EL0";
	case 0xedca:
		return "PMEVCNTR20_EL0";
	case 0xedda:
		return "PMEVCNTR21_EL0";
	case 0xedea:
		return "PMEVCNTR22_EL0";
	case 0xedfa:
		return "PMEVCNTR23_EL0";
	case 0xed8b:
		return "PMEVCNTR24_EL0";
	case 0xed9b:
		return "PMEVCNTR25_EL0";
	case 0xedab:
		return "PMEVCNTR26_EL0";
	case 0xedbb:
		return "PMEVCNTR27_EL0";
	case 0xedcb:
		return "PMEVCNTR28_EL0";
	case 0xeddb:
		return "PMEVCNTR29_EL0";
	case 0xedeb:
		return "PMEVCNTR30_EL0";
	case 0xedfb:
		return "PMEVCNTR31_EL0";
	case 0xf586:
		return "AMEVTYPER00_EL0";
	case 0xf596:
		return "AMEVTYPER01_EL0";
	case 0xf5a6:
		return "AMEVTYPER02_EL0";
	case 0xf5b6:
		return "AMEVTYPER03_EL0";
	case 0xf5c6:
		return "AMEVTYPER04_EL0";
	case 0xf5d6:
		return "AMEVTYPER05_EL0";
	case 0xf5e6:
		return "AMEVTYPER06_EL0";
	case 0xf5f6:
		return "AMEVTYPER07_EL0";
	case 0xf587:
		return "AMEVTYPER08_EL0";
	case 0xf597:
		return "AMEVTYPER09_EL0";
	case 0xf5a7:
		return "AMEVTYPER010_EL0";
	case 0xf5b7:
		return "AMEVTYPER011_EL0";
	case 0xf5c7:
		return "AMEVTYPER012_EL0";
	case 0xf5d7:
		return "AMEVTYPER013_EL0";
	case 0xf5e7:
		return "AMEVTYPER014_EL0";
	case 0xf5f7:
		return "AMEVTYPER015_EL0";
	case 0xf584:
		return "AMEVCNTR00_EL0";
	case 0xf594:
		return "AMEVCNTR01_EL0";
	case 0xf5a4:
		return "AMEVCNTR02_EL0";
	case 0xf5b4:
		return "AMEVCNTR03_EL0";
	case 0xf5c4:
		return "AMEVCNTR04_EL0";
	case 0xf5d4:
		return "AMEVCNTR05_EL0";
	case 0xf5e4:
		return "AMEVCNTR06_EL0";
	case 0xf5f4:
		return "AMEVCNTR07_EL0";
	case 0xf585:
		return "AMEVCNTR08_EL0";
	case 0xf595:
		return "AMEVCNTR09_EL0";
	case 0xf5a5:
		return "AMEVCNTR010_EL0";
	case 0xf5b5:
		return "AMEVCNTR011_EL0";
	case 0xf5c5:
		return "AMEVCNTR012_EL0";
	case 0xf5d5:
		return "AMEVCNTR013_EL0";
	case 0xf5e5:
		return "AMEVCNTR014_EL0";
	case 0xf5f5:
		return "AMEVCNTR015_EL0";
	case 0xf58c:
		return "AMEVCNTR10_EL0";
	case 0xf59c:
		return "AMEVCNTR11_EL0";
	case 0xf5ac:
		return "AMEVCNTR12_EL0";
	case 0xf5bc:
		return "AMEVCNTR13_EL0";
	case 0xf5cc:
		return "AMEVCNTR14_EL0";
	case 0xf5dc:
		return "AMEVCNTR15_EL0";
	case 0xf5ec:
		return "AMEVCNTR16_EL0";
	case 0xf5fc:
		return "AMEVCNTR17_EL0";
	case 0xf58d:
		return "AMEVCNTR18_EL0";
	case 0xf59d:
		return "AMEVCNTR19_EL0";
	case 0xf5ad:
		return "AMEVCNTR110_EL0";
	case 0xf5bd:
		return "AMEVCNTR111_EL0";
	case 0xf5cd:
		return "AMEVCNTR112_EL0";
	case 0xf5dd:
		return "AMEVCNTR113_EL0";
	case 0xf5ed:
		return "AMEVCNTR114_EL0";
	case 0xf5fd:
		return "AMEVCNTR115_EL0";
	case 0xf58e:
		return "AMEVTYPER10_EL0";
	case 0xf59e:
		return "AMEVTYPER11_EL0";
	case 0xf5ae:
		return "AMEVTYPER12_EL0";
	case 0xf5be:
		return "AMEVTYPER13_EL0";
	case 0xf5ce:
		return "AMEVTYPER14_EL0";
	case 0xf5de:
		return "AMEVTYPER15_EL0";
	case 0xf5ee:
		return "AMEVTYPER16_EL0";
	case 0xf5fe:
		return "AMEVTYPER17_EL0";
	case 0xf58f:
		return "AMEVTYPER18_EL0";
	case 0xf59f:
		return "AMEVTYPER19_EL0";
	case 0xf5af:
		return "AMEVTYPER110_EL0";
	case 0xf5bf:
		return "AMEVTYPER111_EL0";
	case 0xf5cf:
		return "AMEVTYPER112_EL0";
	case 0xf5df:
		return "AMEVTYPER113_EL0";
	case 0xf5ef:
		return "AMEVTYPER114_EL0";
	case 0xf5ff:
		return "AMEVTYPER115_EL0";
	case 0xf98c:
		return "PMEVTYPER0_EL0";
	case 0xf99c:
		return "PMEVTYPER1_EL0";
	case 0xf9ac:
		return "PMEVTYPER2_EL0";
	case 0xf9bc:
		return "PMEVTYPER3_EL0";
	case 0xf9cc:
		return "PMEVTYPER4_EL0";
	case 0xf9dc:
		return "PMEVTYPER5_EL0";
	case 0xf9ec:
		return "PMEVTYPER6_EL0";
	case 0xf9fc:
		return "PMEVTYPER7_EL0";
	case 0xf98d:
		return "PMEVTYPER8_EL0";
	case 0xf99d:
		return "PMEVTYPER9_EL0";
	case 0xf9ad:
		return "PMEVTYPER10_EL0";
	case 0xf9bd:
		return "PMEVTYPER11_EL0";
	case 0xf9cd:
		return "PMEVTYPER12_EL0";
	case 0xf9dd:
		return "PMEVTYPER13_EL0";
	case 0xf9ed:
		return "PMEVTYPER14_EL0";
	case 0xf9fd:
		return "PMEVTYPER15_EL0";
	case 0xf98e:
		return "PMEVTYPER16_EL0";
	case 0xf99e:
		return "PMEVTYPER17_EL0";
	case 0xf9ae:
		return "PMEVTYPER18_EL0";
	case 0xf9be:
		return "PMEVTYPER19_EL0";
	case 0xf9ce:
		return "PMEVTYPER20_EL0";
	case 0xf9de:
		return "PMEVTYPER21_EL0";
	case 0xf9ee:
		return "PMEVTYPER22_EL0";
	case 0xf9fe:
		return "PMEVTYPER23_EL0";
	case 0xf98f:
		return "PMEVTYPER24_EL0";
	case 0xf99f:
		return "PMEVTYPER25_EL0";
	case 0xf9af:
		return "PMEVTYPER26_EL0";
	case 0xf9bf:
		return "PMEVTYPER27_EL0";
	case 0xf9cf:
		return "PMEVTYPER28_EL0";
	case 0xf9df:
		return "PMEVTYPER29_EL0";
	case 0xf9ef:
		return "PMEVTYPER30_EL0";
	case 0x8040:
		return "DBGBVR0_EL1";
	case 0x8041:
		return "DBGBVR1_EL1";
	case 0x8042:
		return "DBGBVR2_EL1";
	case 0x8043:
		return "DBGBVR3_EL1";
	case 0x8044:
		return "DBGBVR4_EL1";
	case 0x8045:
		return "DBGBVR5_EL1";
	case 0x8046:
		return "DBGBVR6_EL1";
	case 0x8047:
		return "DBGBVR7_EL1";
	case 0x8048:
		return "DBGBVR8_EL1";
	case 0x8049:
		return "DBGBVR9_EL1";
	case 0x804a:
		return "DBGBVR10_EL1";
	case 0x804b:
		return "DBGBVR11_EL1";
	case 0x804c:
		return "DBGBVR12_EL1";
	case 0x804d:
		return "DBGBVR13_EL1";
	case 0x804e:
		return "DBGBVR14_EL1";
	case 0x804f:
		return "DBGBVR15_EL1";
	case 0x8050:
		return "DBGBCR0_EL1";
	case 0x8051:
		return "DBGBCR1_EL1";
	case 0x8052:
		return "DBGBCR2_EL1";
	case 0x8053:
		return "DBGBCR3_EL1";
	case 0x8054:
		return "DBGBCR4_EL1";
	case 0x8055:
		return "DBGBCR5_EL1";
	case 0x8056:
		return "DBGBCR6_EL1";
	case 0x8057:
		return "DBGBCR7_EL1";
	case 0x8058:
		return "DBGBCR8_EL1";
	case 0x8059:
		return "DBGBCR9_EL1";
	case 0x805a:
		return "DBGBCR10_EL1";
	case 0x805b:
		return "DBGBCR11_EL1";
	case 0x805c:
		return "DBGBCR12_EL1";
	case 0x805d:
		return "DBGBCR13_EL1";
	case 0x805e:
		return "DBGBCR14_EL1";
	case 0x805f:
		return "DBGBCR15_EL1";
	case 0x8060:
		return "DBGWVR0_EL1";
	case 0x8061:
		return "DBGWVR1_EL1";
	case 0x8062:
		return "DBGWVR2_EL1";
	case 0x8063:
		return "DBGWVR3_EL1";
	case 0x8064:
		return "DBGWVR4_EL1";
	case 0x8065:
		return "DBGWVR5_EL1";
	case 0x8066:
		return "DBGWVR6_EL1";
	case 0x8067:
		return "DBGWVR7_EL1";
	case 0x8068:
		return "DBGWVR8_EL1";
	case 0x8069:
		return "DBGWVR9_EL1";
	case 0x806a:
		return "DBGWVR10_EL1";
	case 0x806b:
		return "DBGWVR11_EL1";
	case 0x806c:
		return "DBGWVR12_EL1";
	case 0x806d:
		return "DBGWVR13_EL1";
	case 0x806e:
		return "DBGWVR14_EL1";
	case 0x806f:
		return "DBGWVR15_EL1";
	case 0x8070:
		return "DBGWCR0_EL1";
	case 0x8071:
		return "DBGWCR1_EL1";
	case 0x8072:
		return "DBGWCR2_EL1";
	case 0x8073:
		return "DBGWCR3_EL1";
	case 0x8074:
		return "DBGWCR4_EL1";
	case 0x8075:
		return "DBGWCR5_EL1";
	case 0x8076:
		return "DBGWCR6_EL1";
	case 0x8077:
		return "DBGWCR7_EL1";
	case 0x8078:
		return "DBGWCR8_EL1";
	case 0x8079:
		return "DBGWCR9_EL1";
	case 0x807a:
		return "DBGWCR10_EL1";
	case 0x807b:
		return "DBGWCR11_EL1";
	case 0x807c:
		return "DBGWCR12_EL1";
	case 0x807d:
		return "DBGWCR13_EL1";
	case 0x807e:
		return "DBGWCR14_EL1";
	case 0x807f:
		return "DBGWCR15_EL1";
	default:
		return NULL;
	}
}

char *DisassembleSystemRegisterMoveInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int op2 = getbitsinrange(instruction->hex, 5, 3);
	unsigned int CRm = getbitsinrange(instruction->hex, 8, 4);
	unsigned int CRn = getbitsinrange(instruction->hex, 12, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 16, 3);
	unsigned int o0 = getbitsinrange(instruction->hex, 19, 1);
	unsigned int L = getbitsinrange(instruction->hex, 21, 1);

	const char *sysreg = GetSysReg(2 + o0, CRn, op1, op2, CRm);
	
	// MSR
	if(L == 0){
		if(sysreg){
			disassembled = malloc(128);
			sprintf(disassembled, "msr %s, %s", sysreg, ARM64_GeneralRegisters[Rt]);
		}
		else
			return strdup(".undefined");
	}
	// MRS
	else if(L == 1){
		if(sysreg){
			disassembled = malloc(128);
			sprintf(disassembled, "mrs %s, %s", ARM64_GeneralRegisters[Rt], sysreg);
		}
		else
			return strdup(".undefined");
	}
	else
		return strdup(".unknown");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}

char *DisassembleUnconditionalBranchInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op4 = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int op3 = getbitsinrange(instruction->hex, 10, 6);
	unsigned int op2 = getbitsinrange(instruction->hex, 16, 5);
	unsigned int opc = getbitsinrange(instruction->hex, 21, 4);

	if(op2 != 0x1f)
		return strdup(".undefined");

	// BR, BRAAZ, BRABZ
	if(opc == 0){
		// BR
		if(op3 == 0 && op4 == 0){
			disassembled = malloc(128);
			sprintf(disassembled, "br %s", ARM64_GeneralRegisters[Rn]);
		}
		// BRAAZ or BRABZ
		else if(op4 == 0x1f){
			disassembled = malloc(128);
			
			const char *instr = op3 == 0x2 ? "braaz" : "brabz";
			
			sprintf(disassembled, "%s %s", instr, ARM64_GeneralRegisters[Rn]);
		}
		else
			return strdup(".undefined");
	}
	// BLR, BLRAAZ, BLRABZ
	else if(opc == 1){
		// BLR
		if(op3 == 0 && op4 == 0){
			disassembled = malloc(128);
			sprintf(disassembled, "blr %s", ARM64_GeneralRegisters[Rn]);
		}
		// BLRAAZ or BLRABZ
		else if(op4 == 0x1f){
			disassembled = malloc(128);

			const char *instr = op3 == 0x2 ? "blraaz" : "blrabz";

			sprintf(disassembled, "%s %s", instr, ARM64_GeneralRegisters[Rn]);
		}
		else
			return strdup(".undefined");
	}
	// RET, RETAA, RETAB
	else if(opc == 2){
		if(op3 == 0 && op4 == 0)
			return strdup("ret");
		
		if(op3 == 0x2)
			return strdup("retaa");

		if(op3 == 0x3)
			return strdup("retab");
	
		return strdup(".undefined");
	}
	// ERET, ERETAA, ERETAB
	else if(opc == 4){
		if(op3 == 0 && op4 == 0)
			return strdup("eret");
		
		if(op3 == 0x2)
			return strdup("eretaa");

		if(op3 == 0x3)
			return strdup("eretab");
	
		return strdup(".undefined");
	}
	// DRPS
	else if(opc == 5 && op2 == 0x1f && op3 == 0 && Rn == 0x1f && op4 == 0)
		return strdup("drps");
	// BRAA or BRAB
	else if(opc == 8){
		disassembled = malloc(128);

		const char *instr = "braa";

		if(op3 == 3)
			instr = "brab";

		sprintf(disassembled, "%s %s, %s", instr, ARM64_GeneralRegisters[Rn], op4 == 0x1f ? "sp" : ARM64_GeneralRegisters[op4]);
	}
	// BLRAA, BLRAB
	else if(opc == 9){
		disassembled = malloc(128);

		const char *instr = "blraa";

		if(op3 == 3)
			instr = "blrab";

		sprintf(disassembled, "%s %s, %s", instr, ARM64_GeneralRegisters[Rn], op4 == 0x1f ? "sp" : ARM64_GeneralRegisters[op4]);
	}
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleUnconditionalBranchImmInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op = getbitsinrange(instruction->hex, 31, 1);
	unsigned int imm26 = getbitsinrange(instruction->hex, 0, 26);

	const char *type = "b";

	if(op == 1)
		type = "bl";

	imm26 = sign_extend(imm26 << 2, 28);

	disassembled = malloc(128);

	sprintf(disassembled, "%s #%#lx", type, (signed int)imm26 + instruction->PC);

	return disassembled;
}

char *DisassembleCompareAndBranchImmediateInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int imm19 = getbitsinrange(instruction->hex, 5, 19);
	unsigned int op = getbitsinrange(instruction->hex, 24, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char **registers = ARM64_GeneralRegisters;

	if(sf == 0)
		registers = ARM64_32BitGeneralRegisters;

	imm19 = sign_extend(imm19 << 2, 21);

	const char *instr = op == 0 ? "cbz" : "cbnz";

	disassembled = malloc(128);
	
	sprintf(disassembled, "%s %s, #%#lx", instr, registers[Rt], (signed int)imm19 + instruction->PC);

	return disassembled;
}

char *DisassembleTestAndBranchImmediateInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rt = getbitsinrange(instruction->hex, 0, 5);
	unsigned int imm14 = getbitsinrange(instruction->hex, 5, 14);
	unsigned int b40 = getbitsinrange(instruction->hex, 19, 5);
	unsigned int op = getbitsinrange(instruction->hex, 24, 1);
	unsigned int b5 = getbitsinrange(instruction->hex, 31, 1);

	const char **registers = ARM64_GeneralRegisters;

	if(b5 == 0)
		registers = ARM64_32BitGeneralRegisters;

	const char *instr = "tbz";

	if(op == 1)
		instr = "tbnz";

	unsigned int imm = (b5 << 6) | b40;
	imm14 = sign_extend(imm14 << 2, 16);

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, #%#x, #%#lx", instr, registers[Rt], imm, (signed int)imm14 + instruction->PC);
	
	return disassembled;
}

char *BranchExcSysDisassemble(struct instruction *instruction){
	char *disassembled = NULL;
	
	unsigned int op2 = getbitsinrange(instruction->hex, 0, 5);
	unsigned int op1 = getbitsinrange(instruction->hex, 12, 14);
	unsigned int op0 = getbitsinrange(instruction->hex, 29, 3);
	
	if(op0 == 0x2 && (op1 >> 0xd) == 0)
		disassembled = DisassembleConditionalImmediateBranchInstr(instruction);
	else if(op0 == 0x6){
		if((op1 >> 0xc) == 0)
			disassembled = DisassembleExcGenInstr(instruction);
		else if(op1 == 0x1032 && op2 == 0x1f)
			disassembled = DisassembleHintInstr(instruction);
		else if(op1 == 0x1033)
			disassembled = DisassembleBarrierInstr(instruction);
		else if((op1 & ~0x70) == 0x1004)
			disassembled = DisassemblePSTATEInstr(instruction);
		else if((op1 & ~0x27f) == 0x1080)
			disassembled = DisassembleSystemInstr(instruction);
		else if((op1 & ~0x2ff) == 0x1100)
			disassembled = DisassembleSystemRegisterMoveInstr(instruction);
		else if((op1 >> 0xd) == 0x1)
			disassembled = DisassembleUnconditionalBranchInstr(instruction);
		else
			return strdup(".undefined");
	}
	else if((op0 & ~0x4) == 0)
		disassembled = DisassembleUnconditionalBranchImmInstr(instruction);
	else if((op0 & ~0x4) == 0x1){
		if((op1 >> 0xd) == 0)
			disassembled = DisassembleCompareAndBranchImmediateInstr(instruction);
		else if((op1 >> 0xd) == 0x1)
			disassembled = DisassembleTestAndBranchImmediateInstr(instruction);
	}
	else
		return strdup(".undefined");

	return disassembled;
}
