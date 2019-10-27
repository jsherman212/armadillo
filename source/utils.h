#ifndef _UTILS_H_
#define _UTILS_H_

int HighestSetBit(unsigned int, unsigned int);
int LowestSetBit(unsigned int number, unsigned int n);
unsigned long Ones(int len, int N);
int DecodeBitMasks(unsigned int N, unsigned int imms, unsigned int immr, int immediate, unsigned long *out);
unsigned long Replicate(unsigned long val, unsigned int bits);
unsigned long _Replicate(unsigned int num, int num_bits, int num_times);
int MoveWidePreferred(unsigned int sf, unsigned int immN, unsigned int immr, unsigned int imms);
int IsZero(unsigned long x);
int IsOnes(unsigned long x, int n);
int BFXPreferred(unsigned int sf, unsigned int uns, unsigned int imms, unsigned int immr);
char *decode_reg_extend(unsigned int op);
char *decode_cond(unsigned int cond);
const char *get_arrangement(unsigned int size, unsigned int Q);

#endif
