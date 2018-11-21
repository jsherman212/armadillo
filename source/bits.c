#include "bits.h"

void print_bin(unsigned int integer, int numbytes){
    //int i = CHAR_BIT * sizeof integer; /* however many bits are in an integer */
    int i = numbytes;

	if(numbytes == -1)
		i = CHAR_BIT * sizeof integer;
	
	while(i--) {
        putchar('0' + ((integer >> i) & 1)); 
    }

	printf("\n");
}
unsigned long getbitsinrange(unsigned int number, int start, int amount){
	unsigned int mask = ((1 << amount) - 1) << start;
	return (number & mask) >> start;
}


unsigned int getbitsinrange2(unsigned int number, int start, int amount){
	unsigned int mask = ((1 << amount) - 1) << (start);
	return (number & mask) >> (start);
}

unsigned int sign_extend(unsigned int number, int numbits){
	if(number & (1 << (numbits - 1)))
		return number | ~((1 << numbits) - 1);

	return number;
}

unsigned int sign_extend2(unsigned int number, int numbits){
	int bitstoflip = 32;

	while(bitstoflip > (32 - (numbits - 2))){
		number |= (int)pow(2, bitstoflip);
		bitstoflip--;
	}

	return number;
}

int is_negative(unsigned int number, int size){
	//print_bin((1 << (size - 1)), -1);
	return number & (1 << (size - 1));
}
