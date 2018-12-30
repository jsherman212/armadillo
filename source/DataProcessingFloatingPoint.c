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

char *DisassembleAdvancedSIMDScalarCopyInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);	
	unsigned int imm4 = getbitsinrange(instruction->hex, 11, 4);
	unsigned int imm5 = getbitsinrange(instruction->hex, 16, 5);
	unsigned int op = getbitsinrange(instruction->hex, 29, 1);
	
	int size = LowestSetBit(imm5, 5);

	if(size > 3)
		return strdup(".undefined");

	if(op == 0 && imm4 == 0){
		int index = imm5 >> (size + 1);

		char T = '\0';
		char V = '\0';

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

const char *get_arrangement2(int fp16, unsigned int sz, unsigned int Q){
	if(fp16)
		return Q == 0 ? "4h" : "8h";
	else{
		unsigned int encoding = (sz << 1) | Q;
		
		if(sz == 0)
			return Q == 0 ? "2s" : "4s";
		else		
			return Q == 0 ? "TODO: reserved" : "2d";
	}
}

char *DisassembleAdvancedSIMDThreeSameInstr(struct instruction *instruction, int scalar, int fp16, int extra){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 11, 3);
	unsigned int rot = (opcode & ~0x4);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int sz = (size & 1);
	unsigned int a = (size >> 1);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *_Rd = NULL, *_Rn = NULL, *_Rm = NULL;

	const char sizes[] = {'b', 'h', 's', 'd'};
	const char sz_s[] = {'s', 'd'};

	const char *T = NULL, *instr = NULL;
	const char *Ta = NULL, *Tb = NULL;
	char V = '\0';
	int rotate = 0;
	int add_rotate = 0;

	if(fp16){
		if(U == 0 && a == 0){
			const char **instr_tbl = NULL;

			if(scalar){
				static const char *_temp_tbl[] = {NULL, NULL, NULL, "fmulx", "fcmeq", NULL, NULL, "frecps"};
				instr_tbl = _temp_tbl;
				
				_Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
				_Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
				_Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
			}
			else{
				static const char *_temp_tbl[] = {"fmaxnm", "fmla", "fadd", "fmulx", "fcmeq", NULL, "fmax", "frecps"};
				instr_tbl = _temp_tbl;
			
				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
			}
			
			instr = instr_tbl[opcode];

			if(!instr)
				return strdup(".undefined");

			disassembled = malloc(128);
			
			T = get_arrangement2(fp16, sz, Q);
		}
		else if(U == 0 && a == 1){
			const char **instr_tbl = NULL;

			if(scalar){
				static const char *_temp_tbl[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, "frsqrts"};
				instr_tbl = _temp_tbl;
				
				_Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
				_Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
				_Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
			}
			else{
				static const char *_temp_tbl[] = {"fminnm", "fmls", "fsub", NULL, NULL, NULL, "fmin", "frsqrts"};
				instr_tbl = _temp_tbl;

				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
			}

			instr = instr_tbl[opcode];

			if(!instr)
				return strdup(".undefined");
			
			disassembled = malloc(128);

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(U == 1 && a == 0){
			const char **instr_tbl = NULL;

			if(scalar){
				static const char *_temp_tbl[] = {NULL, NULL, NULL, NULL, "fcmge", "facge"};
				instr_tbl = _temp_tbl;

				_Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
				_Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
				_Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
			}
			else{
				static const char *_temp_tbl[] = {"fmaxnmp", NULL, "faddp", "fmul", "fcmge", "facge", "fmaxp", "fdiv"};
				instr_tbl = _temp_tbl;

				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
			}

			instr = instr_tbl[opcode];

			if(!instr)
				return strdup(".undefined");

			disassembled = malloc(128);
			
			T = get_arrangement2(fp16, sz, Q);
		}
		else if(U == 1 && a == 1){
			const char **instr_tbl = NULL;

			if(scalar){
				static const char *_temp_tbl[] = {NULL, NULL, "fabd", NULL, "fcmgt", "facgt"};
				instr_tbl = _temp_tbl;

				_Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
				_Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
				_Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
			}
			else{
				static const char *_temp_tbl[] = {"fminnmp", NULL, "fabd", NULL, "fcmgt", "facgt", "fminp"};
				instr_tbl = _temp_tbl;

				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
			}

			instr = instr_tbl[opcode];

			if(!instr)
				return strdup(".undefined");

			disassembled = malloc(128);

			T = get_arrangement2(fp16, sz, Q);
		}
		
		if(scalar)
			sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);
		else
			sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, _Rd, T, _Rn, T, _Rm, T);
	
		return disassembled;
	}
	else if(extra){
		// opcode is different with these instructions
		opcode = getbitsinrange(instruction->hex, 11, 4);
		
		if(opcode == 0x2 && (U == 0 || U == 1)){
			instr = U == 0 ? "sdot" : "udot";

			Ta = Q == 0 ? "2s" : "4s";
			Tb = Q == 0 ? "8b" : "16b";
			
			_Rd = ARM64_VectorRegisters[Rd];
			_Rn = ARM64_VectorRegisters[Rn];
			_Rm = ARM64_VectorRegisters[Rm];
			
			disassembled = malloc(128);
			sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, _Rd, Ta, _Rn, Tb, _Rm, Tb);
			
			return disassembled;
		}
		else{
			if(opcode == 0x0){
				if(size == 0 || size == 3)
					return strdup(".undefined");

				instr = "sqrdmlah";
				
				V = size == 1 ? 'h' : 's';
				T = get_arrangement(size, Q);

				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
			}
			else if(opcode == 0x1){
				if(size == 0 || size == 3)
					return strdup(".undefined");

				instr = "sqrdmlsh";

				V = size == 1 ? 'h' : 's';
				T = get_arrangement(size, Q);

				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
			}
			else if((opcode >= 0x8 && opcode <= 0xb) || (opcode >= 0xc && opcode <= 0xe)){
				if(size == 0)
					return strdup(".undefined");

				if(size == 3 && Q == 0)
					return strdup(".undefined");

				add_rotate = 1;

				instr = (opcode >= 0x8 && opcode <= 0xb) ? "fcmla" : "fcadd";

				T = get_arrangement(size, Q);

				_Rd = ARM64_VectorRegisters[Rd];
				_Rn = ARM64_VectorRegisters[Rn];
				_Rm = ARM64_VectorRegisters[Rm];
				
				if(strcmp(instr, "fcmla") == 0){
					if(rot == 0)
						rot = 0;
					else if(rot == 1)
						rot = 90;
					else if(rot == 2)
						rot = 180;
					else
						rot = 270;
				}
				else
					rot = rot == 0 ? 90 : 270;

				printf("rot: %d\n", rot);
			}

			disassembled = malloc(128);
			
			if(scalar)
				sprintf(disassembled, "%s %c%d, %c%d, %c%d", instr, V, Rd, V, Rn, V, Rm);
			else
				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, _Rd, T, _Rn, T, _Rm, T);

			if(add_rotate)
				sprintf(disassembled, "%s, #%d", disassembled, rot);

			return disassembled;
		}
	}
	else{
		opcode = getbitsinrange(instruction->hex, 11, 5);

		if(opcode == 0x0){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "shadd" : "uhadd";

			if(size == 3)
				return strdup(".undefined");

			V = sizes[size];
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x1){
			instr = U == 0 ? "sqadd" : "uqadd";

			V = sizes[size];
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x2){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "srhadd" : "urhadd";

			if(size == 3)
				return strdup(".undefined");

			V = sizes[size];
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x3){
			if(scalar)
				return strdup(".undefined");

			const char *u0[] = {"and", "bic", "orr", "orn"};
			const char *u1[] = {"eor", "bsl", "bit", "bif"};

			instr = U == 0 ? u0[size] : u1[size];

			T = Q == 0 ? "8b" : "16b";
		}
		else if(opcode == 0x4){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "shsub" : "uhsub";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x5){
			instr = U == 0 ? "sqsub" : "uqsub";

			if(size == 3)
				return strdup(".undefined");

			V = sizes[size];
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x6){
			instr = U == 0 ? "cmgt" : "cmhi";

			if(scalar && size != 3)
				return strdup(".undefined");

			V = 'd';
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x7){
			instr = U == 0 ? "cmge" : "cmhs";

			if(scalar && size != 3)
				return strdup(".undefined");

			V = 'd';
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x8){
			instr = U == 0 ? "sshl" : "ushl";

			if(scalar && size != 3)
				return strdup(".undefined");

			V = 'd';
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x9){
			instr = U == 0 ? "sqshl" : "uqshl";

			if(size == 3 && Q == 0)
				return strdup(".undefined");

			V = sizes[size];
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0xa){
			instr = U == 0 ? "srshl" : "urshl";

			if(scalar && size != 3)
				return strdup(".undefined");

			V = 'd';
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0xb){
			instr = U == 0 ? "sqrshl" : "uqrshl";

			if(size == 3 && Q == 0)
				return strdup(".undefined");

			V = sizes[size];
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0xc){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "smax" : "umax";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0xd){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "smin" : "umin";
			
			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0xe){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "sabd" : "uabd";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0xf){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "saba" : "uaba";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x10){
			instr = U == 0 ? "add" : "sub";

			if(scalar && size != 3)
				return strdup(".undefined");

			if(!scalar && (size == 3 && Q == 0))
				return strdup(".undefined");

			V = 'd';
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x11){
			instr = U == 0 ? "cmtst" : "cmeq";

			if(scalar && size != 3)
				return strdup(".undefined");

			if(size == 3 && Q == 0)
				return strdup(".undefined");

			V = 'd';
			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x12){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "mla" : "mls";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x13){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "mul" : "pmul";

			if(size != 0)
				return strdup(".undefined");

			T = Q == 0 ? "8b" : "16b";
		}
		else if(opcode == 0x14){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "smaxp" : "umaxp";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x15){
			if(scalar)
				return strdup(".undefined");

			instr = U == 0 ? "sminp" : "uminp";

			if(size == 3)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x16){
			instr = U == 0 ? "sqdmulh" : "sqrdmulh";

			if(size == 1)
				V = 'h';
			else if(size == 2)
				V = 's';
			else
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x17){
			if(scalar)
				return strdup(".undefined");

			if(U == 1)
				return strdup(".undefined");

			instr = "addp";
			
			if(size == 3 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement(size, Q);
		}
		else if(opcode == 0x18){
			if(scalar)
				return strdup(".undefined");

			if(U == 0)
				instr = a == 0 ? "fmaxnm" : "fminnm";
			else
				instr = a == 0 ? "fmaxnmp" : "fminnmp";

			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x19){
			if(scalar)
				return strdup(".undefined");

			if(U == 0)
				instr = a == 0 ? "fmla" : "fmls";
			else{
				if(size == 0)
					return strdup(".undefined");

				instr = "fmlal2";

				Ta = Q == 0 ? "2s" : "4s";
				Tb = Q == 0 ? "2h" : "4h";

				disassembled = malloc(128);

				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb, ARM64_VectorRegisters[Rm], Tb);
				return disassembled;
			}

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x1a){
			if(scalar){
				if(U != 1 && a != 1)
					return strdup(".undefined");
			}

			if(scalar)
				instr = "fabd";
			else{
				if(U == 0)
					instr = a == 0 ? "fadd" : "fsub";
				else
					instr = a == 0 ? "faddp" : "fabd";
			}

			V = sz_s[sz];

			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x1b){
			if(scalar && U == 1)
				return strdup(".undefined");
			
			if(scalar){
				if(U == 0)
					instr = "fmulx";
			}
			else{
				if(a == 1)
					return strdup(".undefined");

				instr = U == 0 ? "fmulx" : "fmul";
			}

			V = sz_s[sz];

			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x1c){
			if(!scalar && U == 0 && a == 1)
				return strdup(".undefined");
			
			if(U == 0)
				instr = "fcmeq";
			else
				instr = a == 0 ? "fcmge" : "fcmgt";

			V = sz_s[sz];

			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x1d){
			if(scalar && U != 1)
				return strdup(".undefined");

			if(U == 1)
				instr = a == 0 ? "facge" : "facgt";
			else{
				if(size == 0)
					instr = "fmlal";
				else if(size == 2)
					instr = "fmlsl";
				else
					return strdup(".undefined");
			
				Ta = Q == 0 ? "2s" : "4s";
				Tb = Q == 0 ? "2h" : "4h";

				disassembled = malloc(128);

				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb, ARM64_VectorRegisters[Rm], Tb);
				return disassembled;
			}

			V = sz_s[sz];
			
			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x1e){
			if(scalar)
				return strdup(".undefined");

			if(U == 0)
				instr = a == 0 ? "fmax" : "fmin";
			else
				instr = a == 0 ? "fmaxp" : "fminp";

			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		else if(opcode == 0x1f){
			if(scalar)
				return strdup(".undefined");

			if(U == 0)
				instr = a == 0 ? "frecps" : "frsqrts";
			else{
				if(a != 0)
					return strdup(".undefined");

				instr = "fdiv";
			}
			
			if(sz == 1 && Q == 0)
				return strdup(".undefined");

			T = get_arrangement2(fp16, sz, Q);
		}
		
		disassembled = malloc(128);
		
		if(scalar)
			sprintf(disassembled, "%s %c%d, %c%d, %c%d", instr, V, Rd, V, Rn, V, Rm);
		else
			sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T);
	}

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}

char *DisassembleAdvancedSIMDTwoRegisterMiscellaneousInstr(struct instruction *instruction, int scalar, int fp16){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int sz = (size & 1);
	unsigned int a = (size >> 1);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);
	
	const char sizes[] = {'b', 'h', 's', 'd'};
	const char sz_s[] = {'s', 'd'};

	const char *instr = NULL;
	int add_zero = 0;
	char V = '\0';
	const char *T = NULL;
	
	if(opcode == 0x0){
		if(scalar == 1)
			return strdup(".undefined");

		instr = U == 0 ? "rev64" : "rev32";
		
		if(size == 3)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x1){
		if(scalar == 1)
			return strdup(".undefined");

		if(U == 1)
			return strdup(".undefined");

		instr = "rev16";
		
		if(size != 0)
			return strdup(".undefined");

		T = Q == 0 ? "8b" : "16b";
	}
	else if(opcode == 0x2){
		if(scalar == 1)
			return strdup(".undefined");

		instr = U == 0 ? "saddlp" : "uaddlp";

		if(size == 3)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x3){
		instr = U == 0 ? "suqadd" : "usqadd";
		V = sizes[size];
		
		if(scalar == 0 && size == 3 && Q == 0)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x4){
		if(scalar == 1)
			return strdup(".undefined");

		instr = U == 0 ? "cls" : "clz";

		if(size == 3)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x5){
		if(scalar == 1)
			return strdup(".undefined");
		
		instr = "cnt";

		if(U == 1)
			instr = sz == 0 ? "not" : "rbit";
		
		T = Q == 0 ? "8b" : "16b";
	}
	else if(opcode == 0x6){
		if(scalar == 1)
			return strdup(".undefined");

		if(size == 3)
			return strdup(".undefined");

		instr = U == 0 ? "sadalp" : "uadalp";
		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x7){
		instr = U == 0 ? "sqabs" : "sqneg";
		V = sizes[size];
		
		if(scalar == 0 && size == 3 && Q == 0)
			return strdup(".undefined");
		
		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x8){
		instr = U == 0 ? "cmgt" : "cmge";
		add_zero = 1;
		
		if(scalar == 1 && size != 3)
			return strdup(".undefined");

		V = 'd';

		if(scalar == 0 && size == 3 && Q == 0)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0x9){
		instr = U == 0 ? "cmeq" : "cmle";
		add_zero = 1;

		if(scalar == 1 && size != 3)
			return strdup(".undefined");

		V = 'd';
		
		if(scalar == 0 && size == 3 && Q == 0)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0xa){
		if(U == 1)
			return strdup(".undefined");

		instr = "cmlt";
		add_zero = 1;
		
		if(size != 3)
			return strdup(".undefined");

		V = 'd';

		if(scalar == 0 && size == 3 && Q == 0)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0xb){
		instr = U == 0 ? "abs" : "neg";
		
		if(size != 3)
			return strdup(".undefined");

		V = 'd';

		if(scalar == 0 && size == 3 && Q == 0)
			return strdup(".undefined");

		T = get_arrangement(size, Q);
	}
	else if(opcode == 0xc){
		instr = U == 0 ? "fcmgt" : "fcmge";
		add_zero = 1;

		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0xd){
		instr = U == 0 ? "fcmeq" : "fcmle";
		add_zero = 1;

		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0xe){
		if(U == 1)
			return strdup(".undefined");

		instr = "fcmlt";
		add_zero = 1;

		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0xf){
		if(scalar == 1)
			return strdup(".undefined");

		instr = U == 0 ? "fabs" : "fneg";
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x12){
		if(scalar == 0 && U == 0)
			return strdup(".undefined");

		disassembled = malloc(128);

		if(scalar == 0){
			instr = U == 0 ? "xtn" : "sqxtun";

			const char *Tb = NULL, *Ta = NULL;

			if(size == 3)
				return strdup(".undefined");

			Tb = get_arrangement(size, Q);

			if(size == 0)
				Ta = "8h";
			else if(size == 1)
				Ta = "4s";
			else if(size == 2)
				Ta = "2d";

			sprintf(disassembled, "%s%s %s.%s, %s.%s", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta);
			return disassembled;
		}
		else{
			if(size == 3)
				return strdup(".undefined");

			char Vb = sizes[size];
			char Va = '\0';

			if(size == 0)
				Va = 'h';
			else if(size == 1)
				Va = 's';
			else if(size == 2)
				Va = 'd';
			else
				return strdup(".undefined");

			sprintf(disassembled, "%s %c%d, %c%d", instr, Vb, Rd, Va, Rn);
		}
		return disassembled;
	}
	else if(opcode == 0x13){
		if(scalar == 1)
			return strdup(".undefined");

		if(U == 0)
			return strdup(".undefined");

		disassembled = malloc(128);
		instr = "shll";

		const char *Tb = NULL, *Ta = NULL;

		if(size == 3)
			return strdup(".undefined");

		Tb = get_arrangement(size, Q);

		if(size == 0)
			Ta = "8h";
		else if(size == 1)
			Ta = "4s";
		else if(size == 2)
			Ta = "2d";

		sprintf(disassembled, "%s%s %s.%s, %s.%s, #%d", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta, 8 << size);
		return disassembled;
	}
	else if(opcode == 0x14){
		instr = U == 0 ? "sqxtn" : "uqxtn";
		
		disassembled = malloc(128);

		if(scalar == 0){
			const char *Tb = NULL, *Ta = NULL;

			if(size == 3)
				return strdup(".undefined");

			Tb = get_arrangement(size, Q);

			if(size == 0)
				Ta = "8h";
			else if(size == 1)
				Ta = "4s";
			else if(size == 2)
				Ta = "2d";

			sprintf(disassembled, "%s%s %s.%s, %s.%s", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta);
			return disassembled;
		}
		else{
			if(size == 3)
				return strdup(".undefined");

			char Vb = sizes[size];
			char Va = '\0';

			if(size == 0)
				Va = 'h';
			else if(size == 1)
				Va = 's';
			else if(size == 2)
				Va = 'd';
			else
				return strdup(".undefined");

			sprintf(disassembled, "%s %c%d, %c%d", instr, Vb, Rd, Va, Rn);
			return disassembled;
		}
	}
	else if(opcode == 0x16){
		if(U == 0)
			return strdup(".undefined");

		instr = "fcvtxn";

		if(scalar == 0 && U == 0)
			instr = "fcvtn";

		disassembled = malloc(128);

		if(strcmp(instr, "fcvtxn") == 0){
			if(sz == 0)
				return strdup(".undefined");

			if(scalar == 0){
				const char *Tb = NULL, *Ta = "2d";

				Tb = Q == 0 ? "2s" : "4s";
				
				sprintf(disassembled, "%s%s %s.%s, %s.%s", instr, scalar == 0 ? Q == 1 ? "2" : "" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta);
			}
			else{
				char Vb = 's';
				char Va = 'd';

				sprintf(disassembled, "%s%s %c%d, %c%d", instr, scalar == 0 ? Q == 1 ? "2" : "" : "", Vb, Rd, Va, Rn);
				return disassembled;
			}
		}
		else{
			const char *Tb = NULL, *Ta = NULL;

			if(sz == 0){
				Tb = Q == 0 ? "4h" : "8h";
				Ta = "4s";
			}
			else{
				Tb = Q == 0 ? "2s" : "4s";
				Ta = "2d";
			}

			sprintf(disassembled, "%s%s, %s.%s, %s.%s", instr, scalar == 0 ? Q == 1 ? "2" : "" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta);
			return disassembled;
		}
	}
	else if(opcode == 0x17){
		if(scalar == 1)
			return strdup(".undefined");

		if(U == 1)
			return strdup(".undefined");

		disassembled = malloc(128);

		const char *Ta = NULL, *Tb = NULL;

		if(sz == 0){
			Ta = "4s";
			Tb = Q == 0 ? "4h" : "8h";
		}
		else{
			Ta = "2d";
			Tb = Q == 0 ? "2s" : "4s";
		}

		sprintf(disassembled, "%s%s, %s.%s, %s.%s", instr, scalar == 0 ? Q == 1 ? "2" : "" : "", ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb);
		return disassembled;
	}
	else if(opcode == 0x18){
		if(scalar == 1)
			return strdup(".undefined");

		instr = U == 0 ? "frintn" : "frinta";
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x19){
		if(scalar == 1)
			return strdup(".undefined");

		instr = U == 0 ? "frintz" : "frintx";
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x1a){
		if(U == 0)
			instr = a == 0 ? "fcvtns" : "fcvtps";
		else
			instr = a == 0 ? "fcvtnu" : "fcvtpu";

		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x1b){
		if(U == 0)
			instr = a == 0 ? "fcvtms" : "fcvtzs";
		else
			instr = a == 0 ? "fcvtmu" : "fcvtzu";

		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x1c){
		if(U == 0)
			instr = a == 0 ? "fcvtas" : "urecpe";
		else
			instr = a == 0 ? "fcvtau" : "ursqrte";

		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x1d){
		if(U == 0)
			instr = a == 0 ? "scvtf" : "frecpe";
		else
			instr = a == 0 ? "ucvtf" : "frsqrte";
		
		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else if(opcode == 0x1f){
		if(U == 1)
			return strdup(".undefined");
		
		instr = scalar ? "frecpx" : "fsqrt";
		V = sz_s[sz];
		T = get_arrangement2(fp16, sz, Q);
	}
	else
		return strdup(".undefined");

	disassembled = malloc(128);
	
	if(scalar == 0)
		sprintf(disassembled, "%s %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T);
	else{
		if(fp16)
			sprintf(disassembled, "%s %s, %s", instr, ARM64_VectorHalfPrecisionRegisters[Rd], ARM64_VectorHalfPrecisionRegisters[Rn]);
		else
			sprintf(disassembled, "%s %c%d, %c%d", instr, V, Rd, V, Rn);
	}

	if(add_zero)
		sprintf(disassembled, "%s, #0.0", disassembled);

	return disassembled;
}

char *DisassembleAdvancedSIMDThreeDifferentInstr(struct instruction *instruction, int scalar){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 4);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *instr = NULL;
	char Va = '\0', Vb = '\0';
	const char *Ta = NULL, *Tb = NULL;
	
	char Va_s[] = {'\0', 's', 'd'};
	char Vb_s[] = {'\0', 'h', 's'};
	
	const char *Ta_s[] = {"8h", "4s", "2d"};

	const char *instr_tbl_u0[] = {"saddl", "saddw", "ssubl", "ssubw", "addhn", "sabal", 
		"subhn", "sabdl", "smlal", "sqdmlal", "smlsl", "sqdmlsl", 
		"smull", "sqdmull", "pmull"};
	const char *instr_tbl_u1[] = {"uaddl", "uaddw", "usubl", "usubw", "raddhn", "uabal",
		"rsubhn", "uabdl", "umlal", NULL, "umlsl", NULL, 
		"umull", NULL, NULL};
	
	printf("opcode %d\n", opcode);

	if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u0)))
		return strdup(".undefined");

	if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u1)))
		return strdup(".undefined");

	instr = U == 0 ? instr_tbl_u0[opcode] : instr_tbl_u1[opcode];

	if(!instr)
		return strdup(".undefined");

	if(strstr(instr, "pmull"))
		Ta = size == 0 ? "8h" : "1q";
	else
		Ta = Ta_s[size];
	
	Tb = get_arrangement(size, Q);

	if(scalar){
		Va = Va_s[size];
		Vb = Vb_s[size];
	}

	disassembled = malloc(128);

	if(scalar)
		sprintf(disassembled, "%s %c%d, %c%d, %c%d", instr, Va, Rd, Vb, Rn, Vb, Rm);
	else
		sprintf(disassembled, "%s%s %s.%s, %s.%s, %s.%s", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb, ARM64_VectorRegisters[Rm], Tb);

	return disassembled;
}

char *DisassembleAdvancedSIMDModifiedImmediateInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int h = getbitsinrange(instruction->hex, 5, 1);
	unsigned int g = getbitsinrange(instruction->hex, 6, 1);
	unsigned int f = getbitsinrange(instruction->hex, 7, 1);
	unsigned int e = getbitsinrange(instruction->hex, 8, 1);
	unsigned int d = getbitsinrange(instruction->hex, 9, 1);
	unsigned int o2 = getbitsinrange(instruction->hex, 11, 1);
	unsigned int cmode = getbitsinrange(instruction->hex, 12, 4);
	unsigned int c = getbitsinrange(instruction->hex, 16, 1);
	unsigned int b = getbitsinrange(instruction->hex, 17, 1);
	unsigned int a = getbitsinrange(instruction->hex, 18, 1);
	unsigned int op = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);
	
	const char *instr = NULL, *Vt = NULL, *T = NULL, *_Rd = NULL;
	const char *T_8[] = {"8b", "16b"};
	const char *T_16[] = {"4h", "8h"};
	const char *T_32[] = {"2s", "4s"};

	int amount_16[] = {0, 8};
	int amount_32_imm[] = {0, 8, 16, 24};
	int amount_32_ones[] = {8, 16};

	unsigned long imm8 = (a << 7) |
		(b << 6) |
		(c << 5) |
		(d << 4) |
		(e << 3) |
		(f << 2) |
		(g << 1) |
		h;

	int operation = (cmode << 1) | op;
	
	if(cmode != 0xf){
		unsigned long imm = _Replicate(a, 1, 8) << 56 |
			_Replicate(b, 1, 8) << 48 |
			_Replicate(c, 1, 8) << 40 |
			_Replicate(d, 1, 8) << 32 |
			_Replicate(e, 1, 8) << 24 |
			_Replicate(f, 1, 8) << 16 |
			_Replicate(g, 1, 8) << 8 |
			_Replicate(h, 1, 8);
		
		int shifts = 0, shift_amount = 0, use_imm = 0;
		const char *shift_str = NULL;
		
		if((operation & ~0xc) == 0)
			instr = "movi";
		else if((operation & ~0xc) == 1)
			instr = "mvni";
		else if((operation & ~0xc) == 2)
			instr = "orr";
		else if((operation & ~0xc) == 3)
			instr = "bic";
		else if((operation & ~0x4) == 0x10)
			instr = "movi";
		else if((operation & ~0x4) == 0x11)
			instr = "mvni";
		else if((operation & ~0x4) == 0x12)
			instr = "orr";
		else if((operation & ~0x4) == 0x13)
			instr = "bic";
		else if((operation & ~0x2) == 0x18)
			instr = "movi";
		else if((operation & ~0x2) == 0x19)
			instr = "mvni";
		else
			instr = "movi";

		if(strcmp(instr, "movi") == 0){
			if(op == 0){
				if(cmode != 0xe)
					shift_str = (cmode & ~0x1) == 0xc ? "msl" : "lsl";

				if(cmode == 0xe)
					T = T_8[Q];
				else if((cmode & ~0x2) == 0x8){
					T = T_16[Q];
					shift_amount = amount_16[((cmode >> 1) & 1)];
				}
				else{
					T = T_32[Q];
					shift_amount = (cmode & ~0x1) == 0xc ? amount_32_ones[(cmode & 1)] : amount_32_imm[getbitsinrange(cmode, 1, 2)];
				}

				_Rd = ARM64_VectorRegisters[Rd];
			}
			else{
				use_imm = 1;

				if(Q == 0)
					_Rd = ARM64_VectorDoublePrecisionRegisters[Rd];
				else{
					_Rd = ARM64_VectorRegisters[Rd];
					T = "2d";
				}
			}
		}
		else if(strcmp(instr, "orr") == 0){
			shift_str = "lsl";
			
			if((cmode & ~0x2) == 0x9){
				T = T_16[Q];
				shift_amount = amount_16[((cmode >> 1) & 1)];
			}
			else{
				T = T_32[Q];
				shift_amount = amount_32_imm[getbitsinrange(cmode, 1, 2)];
			}

			_Rd = ARM64_VectorRegisters[Rd];
		}
		else if(strcmp(instr, "mvni") == 0){
			_Rd = ARM64_VectorRegisters[Rd];
			
			if((cmode & ~0x2) == 0x9){
				shift_str = "lsl";
				T = T_16[Q];
				shift_amount = amount_16[((cmode >> 1) & 1)];
			}
			else if((cmode & ~0x1) == 0xc){
				shift_str = "msl";
				T = T_32[Q];
				shift_amount = amount_32_ones[(cmode & 1)];
			}
			else{
				shift_str = "lsl";
				T = T_32[Q];
				shift_amount = amount_32_imm[getbitsinrange(cmode, 1, 2)];
			}
		}
		else{
			_Rd = ARM64_VectorRegisters[Rd];
			shift_str = "lsl";

			if((cmode & ~0x2) == 0x9){
				T = T_16[Q];
				shift_amount = amount_16[((cmode >> 1) & 1)];
			}
			else{
				T = T_32[Q];
				shift_amount = amount_32_imm[getbitsinrange(cmode, 1, 2)];
			}
		}

		if(shift_amount > 0)
			shifts = 1;
		
		disassembled = malloc(128);

		sprintf(disassembled, "%s %s", instr, _Rd);
		
		if(T)
			sprintf(disassembled, "%s.%s", disassembled, T);

		sprintf(disassembled, "%s, #%#lx", disassembled, use_imm ? imm : imm8);

		if(shifts)
			sprintf(disassembled, "%s, %s #%d", disassembled, shift_str, shift_amount);
	}
	else{
		instr = "fmov";
		_Rd = ARM64_VectorRegisters[Rd];

		if(op == 1)
			T = "2d";
		else if(o2 == 0)
			T = T_32[Q];
		else
			T = T_16[Q];

		int imm = 0;
		
		imm = a << 31;
		imm |= (b ^ 1) << 30;
		imm |= _Replicate(b, 1, 5) << 25;
		imm |= c << 24;
		imm |= d << 23;
		imm |= e << 22;
		imm |= f << 21;
		imm |= g << 20;
		imm |= h << 19;

		union intfloat {
			int i;
			float f;
		} _if;

		_if.i = imm;
		
		disassembled = malloc(128);
		sprintf(disassembled, "%s %s.%s, #%.1f", instr, _Rd, T, _if.f);
	}			

	return disassembled;
}

const char *get_shift_by_immediate_arrangement(unsigned int immh, unsigned int Q){
	if(immh == 1)
		return Q == 0 ? "8b" : "16b";
	else if((immh & ~0x1) == 2)
		return Q == 0 ? "4h" : "8h";
	else if((immh & ~0x3))
		return Q == 0 ? "2s" : "4s";
	else
		return Q == 0 ? NULL : "2d";
}

const char *get_shift_by_immediate_Ta(unsigned int immh){
	if(immh == 1)
		return "8h";
	else if((immh & ~0x1) == 2)
		return "4s";
	else if((immh & ~0x3) == 4)
		return "2d";
	else
		return NULL;
}

char get_shift_by_immediate_Vb(unsigned int immh){
	if(immh == 1)
		return 'b';
	else if((immh & ~0x1) == 2)
		return 'h';
	else if((immh & ~0x3) == 4)
		return 's';
	else
		return '\0';
}

char get_shift_by_immediate_Va(unsigned int immh){
	if(immh == 1)
		return 'h';
	else if((immh & ~0x1) == 2)
		return 's';
	else if((immh & ~0x3) == 4)
		return 'd';
	else
		return '\0';
}

char get_shift_by_immediate_V(unsigned int immh){
	if(immh == 1)
		return 'b';
	else if((immh & ~0x1) == 2)
		return 'h';
	else if((immh & ~0x3) == 4)
		return 's';
	else
		return 'd';
}

unsigned int get_shift_by_immediate_shift(unsigned int immh, unsigned int immb){
	unsigned int combined = (immh << 3) | immb;

	if(immh == 1)
		return combined - 8;
	else if((immh & ~0x1) == 2)
		return combined - 16;
	else if((immh & ~0x3) == 4)
		return combined - 32;
	else
		return combined - 64;
}

unsigned int get_shift_by_immediate_shift2(unsigned int immh, unsigned int immb){
	unsigned int combined = (immh << 3) | immb;

	if(immh == 1)
		return 16 - combined;
	else if((immh & ~0x1) == 2)
		return 32 - combined;
	else if((immh & ~0x3) == 4)
		return 64 - combined;
	else
		return 128 - combined;
}

char *DisassembleAdvancedSIMDShiftByImmediateInstr(struct instruction *instruction, int scalar){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 11, 5);
	unsigned int immb = getbitsinrange(instruction->hex, 16, 3);
	unsigned int immh = getbitsinrange(instruction->hex, 19, 4);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *Vd = NULL, *Vn = NULL;
	char Va = '\0', Vb = '\0';
	const char *Ta = NULL, *Tb = NULL;
	const char *T = NULL;
	char V = '\0';
	unsigned int shift = 0;
	const char **instr_tbl = NULL;

	const char *instr_tbl_u0[] = {"sshr", NULL, "ssra", NULL, "srshr", NULL, "srsra",
		NULL, NULL, NULL, "shl", NULL, NULL, NULL, "sqshl",
		NULL, "shrn", "rshrn", "sqshrn", "sqrshrn", "sshll",
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, "scvtf",
		NULL, NULL, "fcvtzs"};
	const char *instr_tbl_u1[] = {"ushr", NULL, "usra", NULL, "urshr", NULL, "ursra",		
		NULL, "sri", NULL, "sli", NULL, "sqshlu", NULL, "uqshl",
		NULL, "sqshrun", "sqrshrun", "uqshrn", "uqrshrn",
		"ushll", NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		"ucvtf", NULL, NULL, "fcvtzu"};

	if(U == 0)
		instr_tbl = instr_tbl_u0;
	else
		instr_tbl = instr_tbl_u1;

	const char *instr = instr_tbl[opcode];

	if(!instr)
		return strdup(".undefined");

	if(opcode >= 0x10 && opcode <= 0x14){
		Vb = get_shift_by_immediate_Vb(immh);
		Va = get_shift_by_immediate_Va(immh);
		Tb = get_shift_by_immediate_arrangement(immh, Q);
		Ta = get_shift_by_immediate_Ta(immh);
		
		shift = get_shift_by_immediate_shift2(immh, immb);

		disassembled = malloc(128);
		
		if(scalar)
			sprintf(disassembled, "%s %c%d, %c%d, #%#x", instr, Vb, Rd, Va, Rn, shift);
		else
			sprintf(disassembled, "%s%s %s.%s, %s.%s, #%#x", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta, shift);
	}
	else{
		V = get_shift_by_immediate_V(immh);
		T = get_shift_by_immediate_arrangement(immh, Q);
		
		if(strcmp(instr, "sshr") == 0 || strcmp(instr, "ushr") == 0
				|| strcmp(instr, "ssra") == 0 || strcmp(instr, "usra") == 0
				|| strcmp(instr, "srshr") == 0 || strcmp(instr, "urshr") == 0
				|| strcmp(instr, "srsra") == 0 || strcmp(instr, "ursra") == 0
				|| strcmp(instr, "sri") == 0){
			if((immh & ~0x7) == 0x8)
				shift = 128 - ((immh << 3) | immb);
			else
				return strdup(".undefined");
		}
		else if(strcmp(instr, "shl") == 0 || strcmp(instr, "sli") == 0){
			if((immh & ~0x7) == 0x8)
				shift = 64 - ((immh << 3) | immb);
			else
				return strdup(".undefined");
		}
		else if(strcmp(instr, "sqshl") == 0 || strcmp(instr, "sqshlu") == 0
				|| strcmp(instr, "uqshl") == 0)
			shift = get_shift_by_immediate_shift(immh, immb);
		else if(strcmp(instr, "scvtf") == 0 || strcmp(instr, "fcvtzs") == 0
				|| strcmp(instr, "ucvtf") == 0 || strcmp(instr, "fcvtzu") == 0)
			shift = get_shift_by_immediate_shift2(immh, immb);

		disassembled = malloc(128);

		if(scalar)
			sprintf(disassembled, "%s %c%d, %c%d, #%#x", instr, V, Rd, V, Rn, shift);
		else
			sprintf(disassembled, "%s %s.%s, %s.%s, #%#x", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, shift);
	}

	return disassembled;
}

char *DisassembleAdvancedSIMDIndexedElementInstr(struct instruction *instruction, int scalar){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int H = getbitsinrange(instruction->hex, 11, 1);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 4);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 4);
	unsigned int M = getbitsinrange(instruction->hex, 20, 1);
	unsigned int L = getbitsinrange(instruction->hex, 21, 1);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int a = (size >> 1);
	unsigned int sz = (size & 1);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *instr = NULL;
	const char *Va = NULL, *Vb = NULL, *Vm = NULL;
	const char *Vd = NULL, *Vn = NULL;
	char V = '\0';
	const char *Ta = NULL, *Tb = NULL, *Ts = NULL, *T = NULL;
	
	const char *instr_tbl_u0[] = {(size == 2) ? "fmlal" : NULL, 
		(size == 0 || (size >> 1) == 1) ? "fmla" : NULL,
		"smlal", "sqrdmlal",
		(size == 2) ? "fmlsl" : NULL,
		(size == 0 || (size >> 1) == 1) ? "fmls" : NULL,
		"smlsl", "sqdmlsl", "mul",
		(size == 0 || (size >> 1) == 1) ? "fmul" : NULL,
		"smull", "sqdmull", "sqdmulh", "sqrdmulh", "sdot"};
	
	const char *instr_tbl_u1[] = {"mla",
		(size == 1 || size == 2) ? "fcmla" : NULL,
		"umlal",
		(size == 1 || size == 2) ? "fcmla" : NULL,
		"mls",
		(size == 1 || size == 2) ? "fcmla" : NULL,
		"umlsl",
		(size == 1 || size == 2) ? "fcmla" : NULL,
		(size == 2) ? "fmlal" : NULL,
		(size == 0 || (size >> 1) == 1) ? "fmulx" : NULL,
		"umull", NULL,
		(size == 2) ? "fmlsl" : NULL,
		"sqrdmlah", "udot", "sqrdmlsh"};

	if(U == 0)
		instr = instr_tbl_u0[opcode];
	else
		instr = instr_tbl_u1[opcode];

	if(!instr)
		return strdup(".undefined");

	int index = -1;

	if((U == 0 && (opcode == 0 || opcode == 1
			|| opcode == 4 || opcode == 5
			|| opcode == 9)) || (U == 1 && (opcode == 2 || opcode == 3
			|| opcode == 6 || opcode == 7
			|| opcode == 10 || opcode == 11))){
		if(scalar){
			if(size == 0){
				index = (H << 2) | (L << 1) | M;

				disassembled = malloc(128);
				sprintf(disassembled, "%s %s, %s, %s.h[%d]", instr, ARM64_VectorHalfPrecisionRegisters[Rd], ARM64_VectorHalfPrecisionRegisters[Rn], ARM64_VectorRegisters[Rm], index);
			}
			else{
				V = sz == 0 ? 's' : 'd';
				Vm = ARM64_VectorRegisters[(M << 5) | Rm];
				Ts = sz == 0 ? "s" : "d";
				index = (((sz << 1) | L) >> 1) == 0 ? ((H << 1) | L) : H;
				
				disassembled = malloc(128);
				sprintf(disassembled, "%s %c%d, %c%d, %s.%s[%d]", instr, V, Rd, V, Rn, Vm, Ts, index);
			}
		}
		else{
			if(size == 0){
				index = (H << 2) | (L << 1) | M;
				T = Q == 0 ? "4h" : "8h";

				disassembled = malloc(128);
				sprintf(disassembled, "%s %s.%s, %s.%s, %s.h[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], index);
			}
			else{
				index = (((sz << 1) | L) >> 1) == 0 ? ((H << 1) | L) : H;

				T = Q == 0 ? "2s" : sz == 0 ? "4s" : "2d";
				Ts = sz == 0 ? "s" : "d";

				disassembled = malloc(128);
				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], Ts, index);
			}
		}
	}
	else if((U == 0 && (opcode == 2 || opcode == 3
			|| opcode == 6 || opcode == 7
			|| opcode == 10 || opcode == 11))
			|| (U == 1 && (opcode == 2 || opcode == 6
			|| opcode == 10))){
		if(scalar){
			index = size == 1 ? ((H << 2) | (L << 1) | M) : ((H << 1) | M);

			Va = size == 1 ? "s" : "d";
			Vb = size == 1 ? "h" : "s";
			Vm = size == 1 ? ARM64_VectorRegisters[(0 << 5) | Rm] : ARM64_VectorRegisters[(M << 5) | Rm];

			Ts = size == 1 ? "h" : "s";

			disassembled = malloc(128);
			sprintf(disassembled, "%s %s%d, %s%d, %s.%s[%d]", instr, Va, Rd, Vb, Rn, Vm, Ts, index);
		}
		else{
			index = size == 1 ? ((H << 2) | (L << 1) | M) : ((H << 1) | M);

			Ta = size == 1 ? "4s" : "2d";
			Tb = size == 1 ? Q == 0 ? "4h" : "8h" : Q == 0 ? "2s" : "4s";
			Ts = size == 1 ? "h" : "s";

			disassembled = malloc(128);
			sprintf(disassembled, "%s%s %s.%s, %s.%s, %s.%s[%d]", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb, ARM64_VectorRegisters[Rm], Ts, index);
		}
	}
	else{
		if(scalar){
			V = size == 1 ? 'h' : 's';
			Ts = size == 1 ? "h" : "s";
			index = size == 1 ? ((H << 2) | (L << 1) | M) : ((H << 1) | M);

			disassembled = malloc(128);
			sprintf(disassembled, "%s %c%d, %c%d, %s.%s[%d]", instr, V, Rd, V, Rn, ARM64_VectorRegisters[Rm], Ts, index);
		}
		else{
			T = size == 1 ? Q == 0 ? "4h" : "8h" : Q == 0 ? "2s" : "4s";
			Ts = size == 1 ? "h" : "s";
			index = size == 1 ? (H << 2) | (L << 1) | M : (H << 1) | M;

			disassembled = malloc(128);
			sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], Ts, index);
		}
	}
	
	if(strcmp(instr, "fcmla") == 0)
		sprintf(disassembled, "%s, #%d", disassembled, 90*(int)getbitsinrange(instruction->hex, 13, 2));

	if(!disassembled)
		return strdup(".unknown");

	return disassembled;
}

char *DisassembleAdvancedSIMDScalarPairwiseInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int sz = (size & 1);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);

	const char *instr = NULL, *T = NULL;
	char V = '\0';

	if(opcode == 0x1b){
		if(U == 1)
			return strdup(".undefined");

		instr = "addp";

		if(size != 3)
			return strdup(".undefined");

		V = 'd';
		T = "2d";
	}
	else{
		// subtract 12 so we don't have to deal with rows of annoying NULL
		opcode -= 12;

		if(U == 0){
			if(size == 0){
				const char *tbl[] = {"fmaxnmp", "faddp", NULL, "fmaxp"};

				instr = tbl[opcode];
			}
			else if(size == 2){
				const char *tbl[] = {"fminnmp", NULL, NULL, "fminp"};

				instr = tbl[opcode];
			}
			else
				return strdup(".undefined");

			V = 'h';
			T = "2h";
		}
		else{
			if((size >> 1) == 0){
				const char *tbl[] = {"fmaxnmp", "faddp", NULL, "fmaxp"};

				instr = tbl[opcode];
			}
			else if((size >> 1) == 1){
				const char *tbl[] = {"fminnmp", NULL, NULL, "fminp"};

				instr = tbl[opcode];
			}
			else
				return strdup(".undefined");

			V = sz == 0 ? 's' : 'd';
			T = sz == 0 ? "2s" : "2d";
		}
	}

	disassembled = malloc(128);
	sprintf(disassembled, "%s %c%d, %s.%s", instr, V, Rd, ARM64_VectorRegisters[Rn], T);

	return disassembled;
}

char *DisassembleAdvancedSIMDTableLookupInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int op = getbitsinrange(instruction->hex, 12, 1);
	unsigned int len = getbitsinrange(instruction->hex, 13, 2);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int op2 = getbitsinrange(instruction->hex, 22, 2);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *instr = NULL;
	len++;

	if(op == 0)
		instr = "tbl";
	else
		instr = "tbx";

	const char *Ta = Q == 0 ? "8b" : "16b";

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s.%s, {", instr, ARM64_VectorRegisters[Rd], Ta);

	for(int i=Rn; i<(Rn+len); i++)
		sprintf(disassembled, "%s%s.16b, ", disassembled, ARM64_VectorRegisters[i]);

	disassembled[strlen(disassembled) - 2] = '\0';

	sprintf(disassembled, "%s}, %s.%s", disassembled, ARM64_VectorRegisters[Rm], Ta);
	
	return disassembled;
}

char *DisassembleAdvancedSIMDPermuteInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 3);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	if(opcode == 0 || opcode == 4)
		return strdup(".undefined");

	const char *instr_tbl[] = {NULL, "uzp1", "trn1", "zip1", NULL, "uzp2", "trn2", "zip2"};
	const char *instr = instr_tbl[opcode];

	const char *T = get_arrangement(size, Q);

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T);

	return disassembled;
}

char *DisassembleAdvancedSIMDExtractInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imm4 = getbitsinrange(instruction->hex, 11, 4);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *T = Q == 0 ? "8b" : "16b";

	unsigned int index = 0;

	if(Q == 0 && ((imm4 >> 3) & 1) == 0)
		index = getbitsinrange(imm4, 0, 3);
	else
		index = imm4;

	disassembled = malloc(128);
	sprintf(disassembled, "ext %s.%s, %s.%s, %s.%s, #%d", ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T, index);

	return disassembled;
}

const char *get_advanced_SIMD_copy_arrangement(unsigned int imm5, unsigned int Q){
	if((imm5 & 1) == 1)
		return Q == 0 ? "8b" : "16b";
	else if(((imm5 >> 1) & 1) == 1)
		return Q == 0 ? "4h" : "8h";
	else if(((imm5 >> 2) & 1) == 1)
		return Q == 0 ? "2s" : "4s";
	else if(((imm5 >> 3) & 1) == 1)
		return Q == 0 ? NULL : "2d";
	else
		return NULL;
}

const char *get_advanced_SIMD_copy_specifier(unsigned int imm5){
	if((imm5 & 1) == 1)
		return "b";
	else if(((imm5 >> 1) & 1) == 1)
		return "h";
	else if(((imm5 >> 2) & 1) == 1)
		return "s";
	else if(((imm5 >> 3) & 1) == 1)
		return "d";
	else
		return NULL;
}

char get_advanced_SIMD_gen_width_specifier(unsigned int imm5){
	if((imm5 & 1) == 1)
		return 'w';
	else if(((imm5 >> 1) & 1) == 1)
		return 'w';
	else if(((imm5 >> 2) & 1) == 1)
		return 'w';
	else if(((imm5 >> 3) & 1) == 1)
		return 'x';
	else
		return '\0';
}

unsigned int get_advanced_SIMD_copy_index(unsigned int imm5){
	if((imm5 & 1) == 1)
		return getbitsinrange(imm5, 1, 4);
	else if(((imm5 >> 1) & 1) == 1)
		return getbitsinrange(imm5, 2, 3);
	else if(((imm5 >> 2) & 1) == 1)
		return getbitsinrange(imm5, 3, 2);
	else if(((imm5 >> 3) & 1) == 1)
		return getbitsinrange(imm5, 4, 1);
	else
		return -1;
}

char *DisassembleAdvancedSIMDCopyInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imm4 = getbitsinrange(instruction->hex, 11, 4);
	unsigned int imm5 = getbitsinrange(instruction->hex, 16, 5);
	unsigned int op = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *instr = NULL;
	const char *T = NULL, *Ts = NULL;
	unsigned int index = 0;
	char V = '\0', R = '\0';

	T = get_advanced_SIMD_copy_arrangement(imm5, Q);
	Ts = get_advanced_SIMD_copy_specifier(imm5);
	index = get_advanced_SIMD_copy_index(imm5);
	R = get_advanced_SIMD_gen_width_specifier(imm5);		
	
	if(imm4 == 0 || imm4 == 1){
		disassembled = malloc(128);

		if(imm4 == 0)
			sprintf(disassembled, "dup %s.%s, %s.%s[%d]", ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], Ts, index);
		else
			sprintf(disassembled, "dup %s.%s, %c%d", ARM64_VectorRegisters[Rd], T, R, Rn);
	}
	else if(imm4 == 5){
		disassembled = malloc(128);

		if(Q == 0)
			sprintf(disassembled, "smov %s, %s.%s[%d]", ARM64_32BitGeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);
		else
			sprintf(disassembled, "smov %s, %s.%s[%d]", ARM64_GeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);
	}
	else if(imm4 == 7){
		disassembled = malloc(128);

		if(Q == 0){
			const char *instr = "umov";

			if(((imm5 >> 2) & 1) == 1)
				instr = "mov";

			sprintf(disassembled, "%s %s, %s.%s[%d]", instr, ARM64_32BitGeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);
		}
		else{
			const char *instr = "umov";

			if(((imm5 >> 3) & 1) == 1)
				instr = "mov";

			sprintf(disassembled, "%s %s, %s.%s[%d]", instr, ARM64_GeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);	
		}
	}
	else{
		disassembled = malloc(128);

		if(op == 0)
			sprintf(disassembled, "mov %s.%s[%d], %c%d", ARM64_VectorRegisters[Rd], Ts, index, R, Rn);
		else{
			unsigned int index1 = index;
			unsigned int index2 = 0;

			if((imm5 & 1) == 1)
				index2 = getbitsinrange(imm4, 0, 4);
			else if(((imm5 >> 1) & 1) == 1)
				index2 = getbitsinrange(imm4, 1, 3);
			else if(((imm5 >> 2) & 1) == 1)
				index2 = getbitsinrange(imm4, 2, 2);
			else if(((imm5 >> 3) & 1) == 1)
				index2 = getbitsinrange(imm4, 3, 1);

			sprintf(disassembled, "mov %s.%s[%d], %s.%s[%d]", ARM64_VectorRegisters[Rd], Ts, index1, ARM64_VectorRegisters[Rn], Ts, index2);
		}
	}

	return disassembled;
}

char *DisassembleAdvancedSIMDAcrossLanesInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 12, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int sz = (size & 1);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	const char *instr = NULL;

	const char *instr_tbl_u0[] = {NULL, NULL, NULL, "saddlv", NULL, NULL,
		NULL, NULL, NULL, NULL, "smaxv", NULL,
		(size == 0) ? "fmaxnmv" : "fminnmv",
		NULL, NULL,
		(size == 0) ? "fmaxv" : "fminv",
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		"sminv", "addv"};
	const char *instr_tbl_u1[] = {NULL, NULL, NULL, "addlv", NULL, NULL,
		NULL, NULL, NULL, NULL, "umaxv", NULL,
		((size >> 1) == 0) ? "fmaxnmv" : "fminnmv",
		NULL, NULL,
		((size >> 1) == 0) ? "fmaxv" : "fminv",
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		"uminv", NULL};

	const char *T = NULL;
	char V = '\0';

	char V_tbl[] = {'b', 'h', 's'};
	char V_tbl2[] = {'h', 's', 'd'};

	if(U == 0)
		instr = instr_tbl_u0[opcode];
	else
		instr = instr_tbl_u1[opcode];

	if(opcode == 3){
		V = V_tbl2[size];
		T = get_arrangement(size, Q);
	}
	else if(opcode == 12 || opcode == 15){
		V = U == 0 ? 'h' : 's';
		T = get_arrangement2(U == 0, sz, Q);
	}
	else{
		V = V_tbl[size];
		T = get_arrangement(size, Q);
	}

	disassembled = malloc(128);
	
	sprintf(disassembled, "%s %c%d, %s.%s", instr, V, Rd, ARM64_VectorRegisters[Rn], T);

	return disassembled;
}

char *DisassembleCryptographicThreeRegisterImm2(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 10, 2);
	unsigned int imm2 = getbitsinrange(instruction->hex, 12, 2);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	
	const char *instr_tbl[] = {"sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b"};
	const char *instr = instr_tbl[opcode];

	const char *T = "4s";

	if(strcmp(instr, "sm3tt2b") == 0)
		T = "s";

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s.%s, %s.%s, %s.s[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], imm2);
	
	return disassembled;
}

char *DisassembleCryptographicThreeRegisterSHA512Instr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 10, 2);
	unsigned int O = getbitsinrange(instruction->hex, 14, 1);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);

	const char *instr_tbl_O0[] = {"sha512h", "sha512h2", "sha512su1", "rax1"};
	const char *instr_tbl_O1[] = {"sm3partw1", "sm3partw2", "sm4ekey", NULL};

	const char *instr = NULL;

	if(O == 0)
		instr = instr_tbl_O0[opcode];
	else
		instr = instr_tbl_O1[opcode];

	if(!instr)
		return strdup(".undefined");

	char *_Rd = malloc(32);
	char *_Rn = malloc(32);
	char *_Rm = malloc(32);

	bzero(_Rd, 32);
	bzero(_Rn, 32);
	bzero(_Rm, 32);

	if(strcmp(instr, "sha512h") == 0 || strcmp(instr, "sha512h2") == 0){
		sprintf(_Rd, "q%d", Rd);
		sprintf(_Rn, "q%d", Rn);
		sprintf(_Rm, "v%d.2d", Rm);
	}
	else if(strcmp(instr, "sha512su1") == 0 || strcmp(instr, "rax1") == 0){
		sprintf(_Rd, "v%d.2d", Rd);
		sprintf(_Rn, "v%d.2d", Rn);
		sprintf(_Rm, "v%d.2d", Rm);
	}
	else{
		sprintf(_Rd, "v%d.4s", Rd);
		sprintf(_Rn, "v%d.4s", Rn);
		sprintf(_Rm, "v%d.4s", Rm);
	}

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

	free(_Rd);
	free(_Rn);
	free(_Rm);

	return disassembled;
}

char *DisassembleCryptographicFourRegisterInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int Ra = getbitsinrange(instruction->hex, 10, 5);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int Op0 = getbitsinrange(instruction->hex, 21, 2);

	if(Op0 == 3)
		return strdup(".undefined");

	const char *instr_tbl[] = {"eor3", "bcax", "sm3ss1"};
	const char *instr = instr_tbl[Op0];

	const char *T = "16b";

	if(Op0 == 2)
		T = "4s";

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T, ARM64_VectorRegisters[Ra], T);
	
	return disassembled;
}

char *DisassembleXARInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int imm6 = getbitsinrange(instruction->hex, 10, 6);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);

	disassembled = malloc(128);

	sprintf(disassembled, "xar %s.2d, %s.2d, %s.2d, #%#x", ARM64_VectorRegisters[Rd], ARM64_VectorRegisters[Rn], ARM64_VectorRegisters[Rm], imm6);

	return disassembled;
}

char *DisassembleCryptographicTwoRegisterSHA512Instr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 10, 2);

	disassembled = malloc(128);

	if(opcode == 0)
		sprintf(disassembled, "sha512su0 %s.2d, %s.2d", ARM64_VectorRegisters[Rd], ARM64_VectorRegisters[Rn]);
	else if(opcode == 1)
		sprintf(disassembled, "sm4e %s.4s, %s.4s", ARM64_VectorRegisters[Rd], ARM64_VectorRegisters[Rn]);
	else{
		free(disassembled);
		return strdup(".undefined");
	}

	return disassembled;
}

char *DisassembleConversionBetweenFloatingPointAndFixedPointInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int scale = getbitsinrange(instruction->hex, 10, 6);
	unsigned int opcode = getbitsinrange(instruction->hex, 16, 3);
	unsigned int rmode = getbitsinrange(instruction->hex, 19, 2);
	unsigned int type = getbitsinrange(instruction->hex, 22, 2);
	unsigned int S = getbitsinrange(instruction->hex, 29, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char *instr_tbl[] = {"fcvtzs", "fcvtzu", "scvtf", "ucvtf"};
	const char *instr = instr_tbl[opcode];

	unsigned int fbits = 64 - scale;

	char *_Rd = malloc(24);
	char *_Rn = malloc(24);

	bzero(_Rd, 24);
	bzero(_Rn, 24);

	if(strcmp(instr, "scvtf") == 0 || strcmp(instr, "ucvtf") == 0){
		if(type == 3)
			sprintf(_Rd, "h%d", Rd);
		else if(type == 0)
			sprintf(_Rd, "s%d", Rd);
		else if(type == 1)
			sprintf(_Rd, "d%d", Rd);
		else{
			free(_Rd);
			free(_Rn);
			return strdup(".undefined");
		}
		
		if(sf == 0)
			sprintf(_Rn, "w%d", Rn);
		else
			sprintf(_Rn, "x%d", Rn);
	}
	else{
		if(type == 3)
			sprintf(_Rn, "h%d", Rn);
		else if(type == 0)
			sprintf(_Rn, "s%d", Rn);
		else if(type == 1)
			sprintf(_Rn, "d%d", Rn);
		else{
			free(_Rd);
			free(_Rn);
			return strdup(".undefined");
		}
		
		if(sf == 0)
			sprintf(_Rd, "w%d", Rd);
		else
			sprintf(_Rd, "x%d", Rd);
	}

	disassembled = malloc(128);

	sprintf(disassembled, "%s %s, %s, #%#x", instr, _Rd, _Rn, fbits);

	return disassembled;
}

char *DisassembleConversionBetweenFloatingPointAndIntegerInstr(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 16, 3);
	unsigned int rmode = getbitsinrange(instruction->hex, 19, 2);
	unsigned int type = getbitsinrange(instruction->hex, 22, 2);
	unsigned int S = getbitsinrange(instruction->hex, 29, 1);
	unsigned int sf = getbitsinrange(instruction->hex, 31, 1);

	const char *instr = NULL;

	char *_Rd = malloc(32);
	char *_Rn = malloc(32);

	bzero(_Rd, 32);
	bzero(_Rn, 32);

	if(sf == 0 && S == 0 && type == 0 && rmode == 0){
		const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 0 && rmode == 1){
		const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 0 && rmode == 2){
		const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 0 && rmode == 3){
		const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 1 && rmode == 0){
		const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 1 && rmode == 1){
		const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 1 && rmode == 2){
		const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 1 && rmode == 3){
		const char *instr_tbl[] = {"fcvtzs", "fcvtzu", NULL, NULL, NULL, NULL, "fjcvtzs"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 3 && rmode == 0){
		const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 3 && rmode == 1){
		const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 3 && rmode == 2){
		const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 0 && S == 0 && type == 3 && rmode == 3){
		const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 0 && rmode == 0){
		const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 0 && rmode == 1){
		const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 0 && rmode == 2){
		const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 0 && rmode == 3){
		const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 1 && rmode == 0){
		const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 1 && rmode == 1){
		const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 1 && rmode == 2){
		const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 1 && rmode == 3){
		const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 2 && rmode == 1){
		const char *instr_tbl[] = {NULL, NULL, NULL, NULL, NULL, NULL, "fmov", "fmov", NULL};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 3 && rmode == 0){
		const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 3 && rmode == 1){
		const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 3 && rmode == 2){
		const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
		instr = instr_tbl[opcode];
	}
	else if(sf == 1 && S == 0 && type == 3 && rmode == 3){
		const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
		instr = instr_tbl[opcode];
	}
	else{
		free(_Rd);
		free(_Rn);
		return strdup(".undefined");
	}
	
	if(strstr(instr, "fcvt") || strcmp(instr, "fjcvtzs") == 0){
		if(type == 3)
			sprintf(_Rn, "h%d", Rn);
		else if(type == 0)
			sprintf(_Rn, "s%d", Rn);
		else if(type == 1)
			sprintf(_Rn, "d%d", Rn);
		else{
			free(_Rd);
			free(_Rn);
			return strdup(".undefined");
		}
		
		if(sf == 0)
			sprintf(_Rd, "w%d", Rd);
		else
			sprintf(_Rd, "x%d", Rd);
	}
	else if(strcmp(instr, "fmov") != 0){
		if(type == 3)
			sprintf(_Rd, "h%d", Rd);
		else if(type == 0)
			sprintf(_Rd, "s%d", Rd);
		else if(type == 1)
			sprintf(_Rd, "d%d", Rd);
		else{
			free(_Rd);
			free(_Rn);
			return strdup(".undefined");
		}
		
		if(sf == 0)
			sprintf(_Rn, "w%d", Rn);
		else
			sprintf(_Rn, "x%d", Rn);
	}
	else if(strcmp(instr, "fmov") == 0){
		if(sf == 0 && type == 3 && rmode == 0 && opcode == 6){
			sprintf(_Rd, "w%d", Rd);
			sprintf(_Rn, "h%d", Rn);
		}
		else if(sf == 1 && type == 3 && rmode == 0 && opcode == 6){
			sprintf(_Rd, "x%d", Rd);
			sprintf(_Rn, "h%d", Rn);
		}
		else if(sf == 0 && type == 3 && rmode == 0 && opcode == 7){
			sprintf(_Rd, "h%d", Rd);
			sprintf(_Rn, "w%d", Rn);
		}
		else if(sf == 0 && type == 0 && rmode == 0 && opcode == 7){
			sprintf(_Rd, "s%d", Rd);
			sprintf(_Rn, "w%d", Rn);
		}
		else if(sf == 0 && type == 0 && rmode == 0 && opcode == 6){
			sprintf(_Rd, "w%d", Rd);
			sprintf(_Rn, "s%d", Rn);
		}
		else if(sf == 1 && type == 3 && rmode == 0 && opcode == 7){
			sprintf(_Rd, "h%d", Rd);
			sprintf(_Rn, "x%d", Rn);
		}
		else if(sf == 1 && type == 1 && rmode == 0 && opcode == 7){
			sprintf(_Rd, "d%d", Rd);
			sprintf(_Rn, "x%d", Rn);
		}
		else if(sf == 1 && type == 2 && rmode == 1 && opcode == 7){
			sprintf(_Rd, "v%d.d[1]", Rd);
			sprintf(_Rn, "x%d", Rn);
		}
		else if(sf == 1 && type == 1 && rmode == 0 && opcode == 6){
			sprintf(_Rd, "x%d", Rd);
			sprintf(_Rn, "d%d", Rn);
		}
		else if(sf == 1 && type == 2 && rmode == 1 && opcode == 6){
			sprintf(_Rd, "x%d", Rd);
			sprintf(_Rn, "v%d.d[1]", Rn);
		}
		else
			return strdup(".undefined");
	}

	disassembled = malloc(128);
	
	sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);

	free(_Rd);
	free(_Rn);

	return disassembled;
}

char *DataProcessingFloatingPointDisassemble(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op3 = getbitsinrange(instruction->hex, 10, 9);
	unsigned int op2 = getbitsinrange(instruction->hex, 19, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 23, 2);
	unsigned int op0 = getbitsinrange(instruction->hex, 28, 4);
	/*
	print_bin(op0, 4);
	print_bin(op1, 2);
	print_bin(op2, 4);
	print_bin(op3, 9);
	*/
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
		disassembled = DisassembleAdvancedSIMDScalarCopyInstr(instruction);
	}
	else if(((op0 >> 3) == 0 && (op0 & 1) == 0) && op1 == 0 && (((op2 >> 3) & 1) == 0 && (((op2 >> 2) & 1) == 0)) && (((op3 >> 5) & 1) == 0 && (op3 & 1) == 1)){
		disassembled = DisassembleAdvancedSIMDCopyInstr(instruction);
	}
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && (op1 >> 1) == 0 && ((op2 >> 2) == 2 || ((op2 >> 2) & 1) == 0 || ((op2 >> 2) & 1) == 1) && ((op3 & 1) == 1 || (((op3 >> 5) & 1) == 0 && ((op3 >> 4) & 1) == 0 && (op3 & 1) == 1) || (((op3 >> 5) & 1) == 1 && (op3 & 1) == 1))){
		int scalar = (op0 & 1);
		int fp16 = (op2 >> 2) == 2 && (((op3 >> 5) & 1) == 0 && ((op3 >> 4) & 1) == 0 && (op3 & 1) == 1);
		int extra = ((op2 >> 2) & 1) == 0 && (((op3 >> 5) & 1) == 1 && (op3 & 1) == 1);

		disassembled = DisassembleAdvancedSIMDThreeSameInstr(instruction, scalar, fp16, extra);
	}
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && (op1 >> 1) == 0 && (op2 == 15 || (op2 & ~0x8) == 4) && (((op3 >> 8) & 1) == 0 && ((op3 >> 7) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDTwoRegisterMiscellaneousInstr(instruction, (op0 & 1), op2 == 15);
	}
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 1 && ((((op3 >> 1) & 1) == 0) && ((op3 & 1) == 0))){
		int scalar = (op0 & 1);

		disassembled = DisassembleAdvancedSIMDThreeDifferentInstr(instruction, scalar);
	}
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && op1 == 2 && (op3 & 1) == 1){
		int scalar = ((op0 & ~0x2) == 5);

		if(op2 == 0)
			disassembled = DisassembleAdvancedSIMDModifiedImmediateInstr(instruction);
		else
			disassembled = DisassembleAdvancedSIMDShiftByImmediateInstr(instruction, scalar);
	}
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && (op1 >> 1) == 1 && (op3 & 1) == 0){
		int scalar = ((op0 & ~0x2) == 5);

		disassembled = DisassembleAdvancedSIMDIndexedElementInstr(instruction, scalar);
	}
	else if((op0 & ~0x2) == 5 && (op1 >> 1) == 0 && (op2 & ~0x8) == 6 && (((op3 >> 8) & 1) == 0 && ((op3 >> 7) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDScalarPairwiseInstr(instruction);
	}
	else if((op0 & ~0x4) == 0 && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 0 && (((op3 >> 5) & 1) == 0 && ((op3 >> 1) & 1) == 0 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDTableLookupInstr(instruction);
	}
	else if((op0 & ~0x4) == 0 && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 0 && (((op3 >> 5) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDPermuteInstr(instruction);
	}
	else if((op0 & ~0x4) == 2 && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 0 && (((op3 >> 5) & 1) == 0 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDExtractInstr(instruction);
	}
	else if(((op0 >> 3) == 0 && (op0 & 1) == 0) && (op1 >> 1) == 0 && (op2 & ~0x8) == 6 && (((op3 >> 8) & 1) == 0 && ((op3 >> 7) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDAcrossLanesInstr(instruction);
	}
	else if(op0 == 12 && op1 == 0 && (op2 >> 2) == 2 && (((op3 >> 5) & 1) == 1 && (((op3 >> 4) & 1) == 0))){
		disassembled = DisassembleCryptographicThreeRegisterImm2(instruction);
	}
	else if(op0 == 12 && op1 == 0 && (op2 >> 2) == 3 && (((op3 >> 5) & 1) == 1 && (((op3 >> 3) & 1) == 0 && (((op3 >> 2) & 1) == 0)))){
		disassembled = DisassembleCryptographicThreeRegisterSHA512Instr(instruction);
	}
	else if(op0 == 12 && op1 == 0 && (((op3 >> 5) & 1) == 0)){
		disassembled = DisassembleCryptographicFourRegisterInstr(instruction);
	}
	else if(op0 == 12 && op1 == 1 && ((((op2 >> 3) & 1) == 0 && (((op2 >> 2) & 1) == 0)))){
		disassembled = DisassembleXARInstr(instruction);
	}
	else if(op0 == 12 && op1 == 1 && op2 == 8 && (op3 >> 2) == 8){
		disassembled = DisassembleCryptographicTwoRegisterSHA512Instr(instruction);
	}
	else if((((op0 >> 2) & 1) == 0 && (op0 & 1) == 1) && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 0){
		disassembled = DisassembleConversionBetweenFloatingPointAndFixedPointInstr(instruction);
	}
	else if((((op0 >> 2) & 1) == 0 && (op0 & 1) == 1) && (op1 >> 1) == 0 && ((op2 >> 2) & 1) == 1 && getbitsinrange(op3, 0, 6) == 0){
		disassembled = DisassembleConversionBetweenFloatingPointAndIntegerInstr(instruction);
	}
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}
