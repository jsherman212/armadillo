#ifndef _BITS_H_
#define _BITS_H_

#include <limits.h>
#include <stdio.h>
#include <math.h>

void print_bin(unsigned int, int);

// get bits of a number
// range: [start, end) 
unsigned long getbitsinrange(unsigned int number, int start, int amount);

unsigned int getbitsinrange2(unsigned int number, int start, int amount);

unsigned int sign_extend(unsigned int number, int numbits);
unsigned int sign_extend2(unsigned int number, int numbits);
int is_negative(unsigned int number, int size);
#endif
