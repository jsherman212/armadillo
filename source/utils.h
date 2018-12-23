#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include "bits.h"

int DecodeBitMasks(unsigned int N, unsigned int imms, unsigned int immr, int immediate, unsigned long *out);
int MoveWidePreferred(unsigned int sf, unsigned int immN, unsigned int immr, unsigned int imms);
int IsZero(unsigned long x);
int IsOnes(unsigned long x, int n);
int BFXPreferred(unsigned int sf, unsigned int uns, unsigned int imms, unsigned int immr);

char *decode_reg_extend(unsigned int op);
char *decode_cond(unsigned int cond);

static const char *cond_table[] = { 
	"eq,ne", "cs,cc", "mi,pl", "vs,vc",
	"hi,ls", "ge,lt", "gt,le", "al"
};

#endif
