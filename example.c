#include <stdio.h>
#include <stdlib.h>
#include "armadillo.h"

int main(int argc, char **argv, const char **envp){
	char *disassembled = ArmadilloDisassemble(0xD1008085, 0);
	char *disassembledB = ArmadilloDisassembleB(0x858000D1, 0);
	
	// Will print "sub x5, x4, #0x20"
	printf("%s\n", disassembled);
	printf("%s\n", disassembledB);
	
	free(disassembled);
	free(disassembledB);

	// "b #0x40" in little endian
	char *disassembled2 = ArmadilloDisassemble(0x14000010, 0x100007f30);

	// Will print "b #0x100007f70"
	printf("%s\n", disassembled2);

	free(disassembled2);

	return 0;
}
