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

char *DisassembleAdvancedSIMDScalarThreeSameInstr(struct instruction *instruction, int scalar, int fp16, int extra){
	char *disassembled = NULL;

	unsigned int Rd = getbitsinrange(instruction->hex, 0, 5);
	unsigned int Rn = getbitsinrange(instruction->hex, 5, 5);
	unsigned int opcode = getbitsinrange(instruction->hex, 11, 3);
	unsigned int rot = (opcode & ~0x4);
	unsigned int Rm = getbitsinrange(instruction->hex, 16, 5);
	unsigned int size = getbitsinrange(instruction->hex, 22, 2);
	unsigned int sz = (size & 1);
	unsigned int a = (size >> 1);
	//unsigned int sz = getbitsinrange(instruction->hex, 22, 1);
	//unsigned int a = getbitsinrange(instruction->hex, 23, 1);
	unsigned int U = getbitsinrange(instruction->hex, 29, 1);
	unsigned int Q = getbitsinrange(instruction->hex, 30, 1);

	//const char *_Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
	//const char *_Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
	//const char *_Rm = ARM64_VectorHalfPrecisionRegisters[Rm];

	const char *_Rd = NULL, *_Rn = NULL, *_Rm = NULL;

	const char sizes[] = {'b', 'h', 's', 'd'};
	const char sz_s[] = {'s', 'd'};

	printf("*****scalar: %d, fp16: %d, extra: %d\n", scalar, fp16, extra);
	printf("a: %d\n", a);
	printf("U: %d\n", U);
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
			
			printf("opcode %d\n", opcode);
			instr = instr_tbl[opcode];

			if(!instr)
				return strdup(".undefined");

			disassembled = malloc(128);
			
			T = get_arrangement2(fp16, sz, Q);

		/*	if(scalar)
				sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);
			else
				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, _Rd, T, _Rn, T, _Rm, T);
		*/
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

			/*if(scalar)
				sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);
			else
				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, _Rd, T, _Rn, T, _Rm, T);
		*/
		}
		else if(U == 1 && a == 0){
			//const char *instr_tbl[] = {NULL, NULL, NULL, NULL, "fcmge", "facge"};

			/*if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
				return strdup(".undefined");
			*/

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

		/*	if(scalar)
				sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);
			else
				sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, _Rd, T, _Rn, T, _Rm, T);
		*/
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
		printf("opcode %d\n", opcode);
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
		else{// if(opcode != 0x2){
			printf("hello\n");
			
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
		// TODO: check for size conditions not applying to non-scalar
		printf("other type\n");
		
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
		bzero(disassembled, 128);

		if(scalar)
			sprintf(disassembled, "%s %c%d, %c%d, %c%d", instr, V, Rd, V, Rn, V, Rm);
		else
			sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T);
	}

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}


char *DisassembleAdvancedSIMDScalarTwoRegisterMiscellaneousInstr(struct instruction *instruction, int scalar, int fp16){
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

char *DataProcessingFloatingPointDisassemble(struct instruction *instruction){
	char *disassembled = NULL;

	unsigned int op3 = getbitsinrange(instruction->hex, 10, 9);
	unsigned int op2 = getbitsinrange(instruction->hex, 19, 4);
	unsigned int op1 = getbitsinrange(instruction->hex, 23, 2);
	unsigned int op0 = getbitsinrange(instruction->hex, 28, 4);
	
	print_bin(op0, 4);
	print_bin(op1, 2);
	print_bin(op2, 4);
	print_bin(op3, 9);

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
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && (op1 >> 1) == 0 && ((op2 >> 2) == 2 || ((op2 >> 2) & 1) == 0 || ((op2 >> 2) & 1) == 1) && ((op3 & 1) == 1 || (((op3 >> 5) & 1) == 0 && ((op3 >> 4) & 1) == 0 && (op3 & 1) == 1) || (((op3 >> 5) & 1) == 1 && (op3 & 1) == 1) /*|| ((op3 & 1) == 1)*/)){
		int scalar = (op0 & 1);
		int fp16 = (op2 >> 2) == 2 && (((op3 >> 5) & 1) == 0 && ((op3 >> 4) & 1) == 0 && (op3 & 1) == 1);
		int extra = ((op2 >> 2) & 1) == 0 && (((op3 >> 5) & 1) == 1 && (op3 & 1) == 1);

		disassembled = DisassembleAdvancedSIMDScalarThreeSameInstr(instruction, scalar, fp16, extra);
	}
	else if(((op0 & ~0x2) == 5 || ((op0 >> 3) == 0 && (op0 & 1) == 0)) && (op1 >> 1) == 0 && (op2 == 15 || (op2 & ~0x8) == 4) && (((op3 >> 8) & 1) == 0 && ((op3 >> 7) & 1) == 0 && ((op3 >> 1) & 1) == 1 && (op3 & 1) == 0)){
		disassembled = DisassembleAdvancedSIMDScalarTwoRegisterMiscellaneousInstr(instruction, (op0 & 1), op2 == 15);
	}
	else
		return strdup(".undefined");

	if(!disassembled)
		return strdup(".unknown");
	
	return disassembled;
}
