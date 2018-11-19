#include "armadillo.h"

int main(int argc, char **argp, const char **envp){
	//unsigned long long instr = 0xe7031caa; // MOV X7, X28
	//unsigned int instr = 0xAA0403E7; // mov X7, X4 little endian
	//unsigned int instr = 0x8B010000; // add x0, x0, x1 little endian
	/*unsigned int instr = 0xB103F800; // add x0, x0, #0xfe little endian (data processing - register)

	char *ret = disassemble(instr);

	printf("disassemble returns %s\n\n", ret);

	instr = 0x8B010000; // add x0, x0, x1 little endian
	ret = disassemble(instr);
	printf("disassemble returns %s\n\n", ret);
*/
	unsigned int instrs[] = { 0xAA0403E7, 0x8B010000, 0xB103F800, 0xAA1C03E7 };

	for(int i=0; i<sizeof(instrs)/sizeof(unsigned int); i++){
		char *ret = disassemble(instrs[i]);
		printf("disassemble returns %s\n\n", ret);
	}

	return 0;
}
