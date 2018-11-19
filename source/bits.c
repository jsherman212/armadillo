#include "bits.h"

unsigned int getbitsinrange(unsigned int number, int start, int amount){
	unsigned int mask = ((1 << amount) - 1) << start;
	return (number & mask) >> start;
}
