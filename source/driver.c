#include "armadillo.h"
#include "linkedlist.h"


struct testinstr {
	const char *name;
	unsigned int hex;
};

struct linkedlist *instructions = NULL;

void addinstr(const char *name, unsigned int hex){
	if(!instructions)
		return;


	struct testinstr *i = malloc(sizeof(struct testinstr));
	i->name = name;
	i->hex = hex;

	linkedlist_add(instructions, i);
}

int main(int argc, char **argp, const char **envp){
	instructions = linkedlist_new();


	//addinstr("mov x7, x4", 0xAA0403E7);
	//addinstr("add x0, x0, x1", 0x8B010000);
	addinstr("add x0, x0, #0xfe", 0x9103F800);
	addinstr("add x0, x0, #8388608", 0x91600000);
	addinstr("adds x0, x0, #0xfe", 0xB103F800);
	addinstr("add w0, w0, #0xfe", 0x1103F800);
	addinstr("add w0, w0, #0xfe, lsl #12", 0x1143F800);
	addinstr("add w3, wsp, #0", 0x110003E3);
	addinstr("adds xzr, sp, #4", 0xB10013FF);
	addinstr("sub x4, x2, #4", 0xD1001044);
	addinstr("sub x4, x2, #0x800, lsl 12", 0xD1600044);
	addinstr("sub w5, w11, #20", 0x51005165);
	addinstr("subs w9, w16, #3444", 0x7135D209);
	addinstr("subs x11, x25, #16384", 0xF140132B);
	addinstr("subs wzr, w3, #8192", 0x7140087F);
	addinstr("subs xzr, x14, #4192", 0xF14005DF);
	addinstr("subs xzr, sp, #2048", 0xF12003FF);


	addinstr("and x0, x2, #4", 0x927E0040);
	addinstr("and x6, x18, #-16", 0x927CEE46);
	addinstr("and x25, x22, #8388608", 0x926902D9);
	addinstr("and x25, x22, #-4194304", 0x926AA6D9);
	addinstr("and w8, w14, #1", 0x120001C8);
	addinstr("and w18, w1, #-16", 0x121C6C32);

	addinstr("orr x9, x3, #30", 0xB27F0C69);
	addinstr("orr w20, w0, #-16", 0x321C6C14);
	addinstr("orr w16, w4, #-0x800000", 0x32092090);
	addinstr("orr w4, w31, #0x80000003", 0x32010BE1);
	addinstr("orr x8, xzr, xzr", 0xAA1F03E8);
	


	addinstr("eor wsp, w3, #0x80000003", 0x5201087F);
	addinstr("eor x6, x3, #0xffff", 0xD2403C66);
	addinstr("eor x24, x8, #-0x400000", 0xD26AA518);
	addinstr("ands x0, x1, #0x6", 0xF27F0420);
	addinstr("ands w5, w4, #-0x4", 0x721E7485);

	struct node_t *current = instructions->front;

	while(current){
		struct testinstr *ti = (struct testinstr *)current->data;
		printf("Disassembling %s (aka %#x)... ", ti->name, ti->hex);
		char *ret = disassemble(ti->hex);
		printf("Disassembled: %s\n\n", ret);
		free(ret);

		current = current->next;
	}

	linkedlist_free(instructions);

	/*unsigned int instrs[] = { 0xAA0403E7, 0x8B010000, 0x9103F800, 0x91600000, 0xB103F800, 0x1103F800, 0x1143F800, 0x110003E3, 0xAA1C03E7, 0x10020017, 0x10FE0017, 0xB0001A24, 0xB0FFDDF5, 0x9000003E, 0x90FFFFFE, 0x3000002F, 0x70FFFFC3 };
	const char *instrstrs[] = { "mov x7, x4", 
								"add x0, x0, x1",
								"add x0, x0, #0xfe",
								"add x0, x0, #8388608",
								"adds x0, x0, #0xfe",
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
	*/
	return 0;
}
