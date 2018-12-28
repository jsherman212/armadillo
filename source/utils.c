#include "utils.h"
#include <math.h>

int HighestSetBit(unsigned int number, int n){
	int ret = -1;
	
	for(int i = n-1; i>=0; i--){
		if(number & (1 << i))
			return i;
	}

	return ret;
}

int LowestSetBit(int number, int n){
	int ret = n;

	for(int i=0; i<n; i++){
		if(number & (1 << i))
			return i;
	}

	return ret;
}

unsigned long Ones(int len, int N){
	(void)N;
	unsigned long ret = 0;
	
	for(int i=len-1; i>=0; i--)
		ret |= ((unsigned long)1 << i);
	
	return ret;
}

/* Thanks https://github.com/xerub/macho/blob/master/patchfinder64.c */
unsigned long RORZeroExtendOnes(unsigned int M, unsigned int N, unsigned int R){
	unsigned long val = Ones(M, N);
	
	if(R == 0)
		return val;
		
	return ((val >> R) & (((unsigned long)1 << (N - R)) - 1)) | ((val & (((unsigned long)1 << R) - 1)) << (N - R));
}

/* Thanks https://github.com/xerub/macho/blob/master/patchfinder64.c */
unsigned long Replicate(unsigned long val, unsigned int bits){
	unsigned long ret = val;
	
	for(unsigned int shift = bits; shift < 32; shift += bits)
		ret |= (val << shift);
	
	return ret;
}

unsigned long Replicate2(unsigned long val, unsigned int N){
	return (1ULL << N) - 1;
}

unsigned long _Replicate(unsigned int num, int num_bits, int num_times){
	unsigned long result = 0;
	for(int i=0; i<num_times; i++){
		result <<= num_bits;
		result |= num;
	}
	return result;
}

unsigned long AdvSIMDExpandImm(unsigned int op, unsigned int cmode, unsigned int imm8, unsigned long *imm64){
	//unsigned long imm64 = 0;
	
	cmode >>= 1;

	if(cmode == 0){
		//unsigned long zeros = Replicate(0, 24);
		//zeros <<= 8;
		//zeros |= imm8;
		//print_bin(zeros, 32);
		//return Replicate(
		*imm64 = Replicate2(imm8, 2);
	}
	else if(cmode == 1){
		*imm64 = Replicate2(imm8 << 8, 2);
	}
	else if(cmode == 2){
		//imm64 = imm8 << 16;
		*imm64 = Replicate2(imm8 << 16, 2);
		//print_bin(imm8 << 16, -1);
	}
	else if(cmode == 3){
		*imm64 = Replicate2(imm8 << 24, 2);
	}
	else if(cmode == 4){
		imm8 = (short)imm8;
		*imm64 = Replicate2(imm8, 4);
	}
	else if(cmode == 5){
		*imm64 = Replicate2((short)imm8 << 8, 4);
	}
	else if(cmode == 6){
		if((cmode & 1) == 0)
			*imm64 = Replicate2((imm8 << 8) | Ones(8, 0), 2);
		else
			*imm64 = Replicate2((imm8 << 16) | Ones(16, 0), 2);
	}
	else if(cmode == 7){
		if((cmode & 1) == 0 && op == 0)
			*imm64 = Replicate2(imm8, 8);
		else if((cmode & 1) == 0 && op == 1){
			unsigned long imm8a, imm8b, imm8c, imm8d, imm8e, imm8f, imm8g, imm8h;

			imm8a = Replicate2(((imm8 >> 7) & 1), 8);
			imm8b = Replicate2(((imm8 >> 6) & 1), 8);
			imm8c = Replicate2(((imm8 >> 5) & 1), 8);
			imm8d = Replicate2(((imm8 >> 4) & 1), 8);
			imm8e = Replicate2(((imm8 >> 3) & 1), 8);
			imm8f = Replicate2(((imm8 >> 2) & 1), 8);
			imm8g = Replicate2(((imm8 >> 1) & 1), 8);
			imm8h = Replicate2((imm8 & 1), 8);

			*imm64 = (imm8a << 56) |
				(imm8b << 48) |
				(imm8c << 40) |
				(imm8d << 32) |
				(imm8e << 24) |
				(imm8f << 16) |
				(imm8g << 8) |
				imm8h;
		}
		else if((cmode & 1) == 1 && op == 0){
			unsigned int imm32 = 0;
			imm32 = ((imm8 >> 7) & 1) << 31;
			imm32 |= ~((imm8 >> 6) & 1) << 30;
			imm32 |= Replicate2(((imm8 >> 6) & 1), 5) << 25;
			imm32 |= (imm8 << 3) << 19;
			
			*imm64 = Replicate2(imm32, 2);
		}
		else if((cmode & 1) == 1 && op == 1){
			//imm8 = (unsigned long)imm8;
			
			/*unsigned long a = ((imm8 >> 7) & 1);
			unsigned long b = ~((imm8 >> 6) & 1);
			unsigned long c = Replicate2(((imm8 >> 6) & 1), 8);
			unsigned long d = (imm8 & 63);
			
			*imm64 |= a << 63;
						
			printf("imm64 #%#lx\n", *imm64);
			print_bin_long(*imm64, 64);
			*imm64 |= b << 62;
			printf("imm64 #%#lx\n", *imm64);
			print_bin_long(*imm64, 64);
			*imm64 |= c << 54;
			printf("imm64 #%#lx\n", *imm64);
			print_bin_long(*imm64, 64);
			*imm64 |= d << 48;
			printf("imm64 #%#lx\n", *imm64);
			
			print_bin_long(*imm64, 64);
			
			//c*imm64 = (*imm64 >> 48) << 48;

			//print_bin(*imm64, 64);
			printf("imm64 #%#lx\n", *imm64);
			*/
			/*
			imm64 = ((unsigned long)((imm8 >> 7) & 1)) << 63;
			imm64 |= (~(unsigned long)((imm8 >> 6) & 1)) << 62;
			imm64 |= Replicate2(((imm8 >> 6) & 1), 8) << 54;
			imm64 |= ((unsigned long)(imm8 & 63)) << 48;
			*/
		
		}
	}

	printf("cmode %d\n", cmode);
	//return imm64;
	return 2;
}

int DecodeBitMasks(unsigned int N, unsigned int imms, unsigned int immr, int immediate, unsigned long *out){
	// & 0x3f zeros everything except the first 7 bits
	// argument to HighestSetBit is N:NOT(imms)
	unsigned int num = (N << 6) | (~imms & 0x3f);
	unsigned int len = HighestSetBit(num, 7);
	
	if(len < 1)
		return -1;
	
	unsigned int levels = Ones(len, 0);

	if(immediate && ((imms & levels) == levels))
		return -1;

	unsigned int S = imms & levels;
	unsigned int R = immr & levels;
	unsigned int esize = 1 << len;
	
	*out = Replicate(RORZeroExtendOnes(S + 1, esize, R), esize);

	return 0;
}

int MoveWidePreferred(unsigned int sf, unsigned int immN, unsigned int immr, unsigned int imms){
	int width = sf == 1 ? 64 : 32;
	unsigned int combined = (immN << 6) | imms;

	if(sf == 1 && (combined >> 6) != 1)
		return 0;
	
	if(sf == 0 && (combined >> 5) != 0)
		return 0;

	if(imms < 16)
		return (-immr % 16) <= (15 - imms);

	if(imms >= (width - 15))
		return (immr % 16) <= (imms - (width - 15));

	return 0;
}

int IsZero(unsigned long x){
	return x == 0;
}

int IsOnes(unsigned long x, int n){
	return x == Ones(n, 0);
}

int BFXPreferred(unsigned int sf, unsigned int uns, unsigned int imms, unsigned int immr){
	if(imms < immr)
		return 0;

	if(imms == ((sf << 6) | 0x3f))
		return 0;

	if(immr == 0){
		if(sf == 0 && (imms == 0x7 || imms == 0xf))
			return 0;
		else if(((sf << 1) | uns) == 0x2 && (imms == 0x7 || imms == 0xf || imms == 0x1f))
			return 0;
	}

	return 1;
}

char *decode_reg_extend(unsigned int op){
	switch(op){
	case 0x0:
		return "uxtb";
	case 0x1:
		return "uxth";
	case 0x2:
		return "uxtw";
	case 0x3:
		return "uxtx";
	case 0x4:
		return "sxtb";
	case 0x5:
		return "sxth";
	case 0x6:
		return "sxtw";
	case 0x7:
		return "sxtx";
	default:
		return NULL;
	};
}

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

int check_bounds(int index, int size){
	return index >= 0 && index < size;
}

const char *get_arrangement(unsigned int size, unsigned int Q){
	if(size == 0)
		return Q == 0 ? "8b" : "16b";
	if(size == 1)
		return Q == 0 ? "4h" : "8h";
	if(size == 2)
		return Q == 0 ? "2s" : "4s";
	if(size == 3)
		return Q == 0 ? "1d" : "2d";
	
	// should never reach
	return NULL;
}
