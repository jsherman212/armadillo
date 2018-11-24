#include "utils.h"

int HighestSetBit(unsigned int number, int n){
	int ret = -1;
	
	for(int i = n-1; i>=0; i--){
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

	if(imms < 16){
		return (-immr % 16) <= (15 - imms);
	}

	if(imms >= (width - 15))
		return (immr % 16) <= (imms - (width - 15));

	return 0;
}
