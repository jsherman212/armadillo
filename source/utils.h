#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include "bits.h"

int DecodeBitMasks(unsigned int N, unsigned int imms, unsigned int immr, int immediate, unsigned long *out);
int MoveWidePreferred(unsigned int sf, unsigned int immN, unsigned int immr, unsigned int imms);


#endif
