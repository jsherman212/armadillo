#include "bits.h"

unsigned long getbitsinrange(unsigned int number, int start, int amount){
    unsigned int mask = ((1 << amount) - 1) << start;
    return (number & mask) >> start;
}

unsigned int sign_extend(unsigned int number, int numbits){
    if(number & (1 << (numbits - 1)))
        return number | ~((1 << numbits) - 1);

    return number;
}
