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
	unsigned int instrs[] = { 0xAA0403E7, 0x8B010000, 0x9103F800, 0x91600000, 0x1103F800, 0x1143F800, 0x110003E3, 0xAA1C03E7, 0x10020017, 0x10FE0017, 0xB0001A24, 0xB0FFDDF5, 0x9000003E, 0x90FFFFFE, 0x3000002F, 0x70FFFFC3 };
	const char *instrstrs[] = { "mov x7, x4", 
								"add x0, x0, x1",
								"add x0, x0, #0xfe",
								"add x0, x0, #8388608",
								"add w0, w0, #0xfe",
								"add w0, w0, #0xfe, lsl #12",
								"add w3, wsp, #0",
								"mov x7, x28",
								"adr x23, 0x4000",
								"adr x23, -0x4000",
								"adrp x4, 0x345000",
   								"adrp x21, -0x443000",
								"adrp x30, 0x4000",
								"adrp x30, -0x4000",
								"adr x15, 0x5",
								"adr x3, -0x5"
	};

	for(int i=0; i<sizeof(instrs)/sizeof(unsigned int); i++){
		printf("Disassembling %s (aka %#x)... ", instrstrs[i], instrs[i]);
		char *ret = disassemble(instrs[i]);
		printf("Disassembled: %s\n\n", ret);
		free(ret);
	}
	
	return 0;
}
