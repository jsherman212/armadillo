#include "armadillo.h"
#include "linkedlist.h"

struct testinstr {
	const char *name;
	unsigned int hex;
	unsigned long PC;
};

struct linkedlist *instructions = NULL;

void addinstr(const char *name, unsigned int hex, unsigned long PC){
	if(!instructions)
		return;


	struct testinstr *i = malloc(sizeof(struct testinstr));
	i->name = name;
	i->hex = hex;
	i->PC = PC;

	linkedlist_add(instructions, i);
}

int main(int argc, char **argp, const char **envp){
	instructions = linkedlist_new();


	//addinstr("mov x7, x4", 0xAA0403E7);
	//addinstr("add x0, x0, x1", 0x8B010000);
	/*addinstr("add x0, x0, #0xfe", 0x9103F800, 0);
	addinstr("add x0, x0, #8388608", 0x91600000, 0);
	addinstr("adds x0, x0, #0xfe", 0xB103F800, 0);
	addinstr("add w0, w0, #0xfe", 0x1103F800, 0);
	addinstr("add w0, w0, #0xfe, lsl #12", 0x1143F800, 0);
	addinstr("add w3, wsp, #0", 0x110003E3, 0);
	addinstr("adds xzr, sp, #4", 0xB10013FF, 0);
	addinstr("sub x4, x2, #4", 0xD1001044, 0);
	addinstr("sub x4, x2, #0x800, lsl 12", 0xD1600044, 0);
	addinstr("sub w5, w11, #20", 0x51005165, 0);
	addinstr("subs w9, w16, #3444", 0x7135D209, 0);
	addinstr("subs x11, x25, #16384", 0xF140132B, 0);
	addinstr("subs wzr, w3, #8192", 0x7140087F, 0);
	addinstr("subs xzr, x14, #4192", 0xF14005DF, 0);
	addinstr("subs xzr, sp, #2048", 0xF12003FF, 0);

	addinstr("and x0, x2, #4", 0x927E0040, 0);
	addinstr("and x6, x18, #-16", 0x927CEE46, 0);
	addinstr("and x25, x22, #8388608", 0x926902D9, 0);
	addinstr("and x25, x22, #-4194304", 0x926AA6D9, 0);
	addinstr("and w8, w14, #1", 0x120001C8, 0);
	addinstr("and w18, w1, #-16", 0x121C6C32, 0);

	addinstr("orr x9, x3, #30", 0xB27F0C69, 0);
	addinstr("orr w20, w0, #-16", 0x321C6C14, 0);
	addinstr("orr w16, w4, #-0x800000", 0x32092090, 0);
	addinstr("orr w4, w31, #0x80000003", 0x32010BE1, 0);
	addinstr("orr x8, xzr, xzr", 0xAA1F03E8, 0);
	


	addinstr("eor wsp, w3, #0x80000003", 0x5201087F, 0);
	addinstr("eor x6, x3, #0xffff", 0xD2403C66, 0);
	addinstr("eor x24, x8, #-0x400000", 0xD26AA518, 0);
	addinstr("ands x0, x1, #0x6", 0xF27F0420, 0);
	addinstr("ands w5, w4, #-0x4", 0x721E7485, 0);

	addinstr("adrp x8, #0x100046000 @ 0x10000a7e8", 0x900001e8, 0x10000a7e8);
	addinstr("adrp x1, #0x10000a000 @ 0x10000a79c", 0x90000001, 0x10000a79c);
	addinstr("sub sp, sp, #0x80", 0xd10203ff, 0);
	

	addinstr("movn w0, #39333", 0x129334A0, 0);
	addinstr("movn x5, #65535", 0x929FFFE5, 0);
	addinstr("movn x19, #3443, lsl #32", 0x92C1AE73, 0);
	addinstr("movn w2, #20, lsl #16", 0x12A00282, 0);
	addinstr("movn x2, #20, lsl #16", 0x92A00282, 0);

	addinstr("movz w0, #40, lsl #16", 0x52A00500, 0);
	addinstr("movz x6, #9833, lsl #48", 0xD2E4CD26, 0);
	addinstr("movz x16, #34335, lsl #32", 0xD2D0C3F0, 0);
	addinstr("movz w4, #2292", 0x52811E84, 0);
	addinstr("movz x21, #2", 0xD2800055, 0);

	addinstr("movk w5, #4943, lsl #16", 0x72A269E5, 0);
	addinstr("movk x10, #2321, lsl #48", 0xF2E1222A, 0);
	addinstr("movk x8, #4848, lsl #32", 0xF2C25E08, 0);
	addinstr("movk x25, #0", 0xF2800019, 0);
	addinstr("movk w23, #2", 0x72800057, 0);

	addinstr("sbfm x0, x2, #4, #5", 0x93441440, 0);
	addinstr("sbfm w3, w14, #4, #6", 0x130419C3, 0);
	addinstr("sbfm x31, x2, #4, #34", 0x9344885F, 0);
	addinstr("sbfm x0, x2, #22, #31", 0x93567C40, 0);
	addinstr("sbfm x31, x2, #4, #0x3f", 0x9344FC5F, 0);
	addinstr("sbfm w31, w2, #4, #0x1f", 0x13047C5F, 0);
	addinstr("sbfm x4, x14, #4, #2", 0x934409C4, 0);
	addinstr("sbfm x8, x1, #32, #24", 0x93606028, 0);
	addinstr("sbfm w21, w13, #16, #8", 0x131021B5, 0);
	addinstr("sbfm x4, x12, #0, #7", 0x93401D84, 0);
	addinstr("sbfm w5, w1, #0, #7", 0x13001C25, 0);
	addinstr("sbfm w0, w6, #0, #15", 0x13003CC0, 0);
	addinstr("sbfm x2, x20, #0, #15", 0x93403E82, 0);
	addinstr("sbfm w3, w4, #0, #31", 0x13007C83, 0);
	addinstr("sbfm x19, x9, #0, #31", 0x93407D3F, 0);
	


	addinstr("bfm x0, x31, #4, #2", 0xB3440BE0, 0);
    addinstr("bfm w3, w31, #4, #2", 0x33040BE3, 0);
    addinstr("bfm x31, x2, #4, #34", 0xB344885F, 0);
    addinstr("bfm x0, x2, #22, #31", 0xB3567C40, 0);
    addinstr("bfm x31, x2, #4, #8", 0xB344205F, 0);
    addinstr("bfm w31, w2, #4, #0x1f", 0x33047C5F, 0);
    addinstr("bfm x4, x14, #4, #2", 0xB34409C4, 0);
    addinstr("bfm x8, x1, #32, #24", 0xB3606028, 0);
    addinstr("bfm w21, w13, #16, #8", 0x331021B5, 0);
    addinstr("bfm x4, x12, #0, #7", 0xB3401D84, 0);
    addinstr("bfm w5, w1, #0, #7", 0x33001C25, 0);
    addinstr("bfm w0, w6, #0, #15", 0x33003CC0, 0);
    addinstr("bfm x2, x20, #0, #15", 0xB3403E82, 0);
    addinstr("bfm w3, w4, #0, #31", 0x33007C83, 0);
    addinstr("bfm x19, x9, #0, #31", 0xB3407D33, 0);



	addinstr("ubfm x3, x4, #8, #7", 0xD3481C83, 0);
    addinstr("ubfm w4, w1, #15, #14", 0x530F3824, 0);
    addinstr("ubfm x0, x31, #4, #2", 0xD3440BE0, 0);
    addinstr("ubfm w3, w31, #4, #2", 0x53040BE3, 0);
    addinstr("ubfm x31, x2, #4, #34", 0xD344885F, 0);
    addinstr("ubfm x0, x2, #22, #31", 0xD3567C40, 0);
    addinstr("ubfm x31, x2, #4, #8", 0xD344205F, 0);
    addinstr("ubfm w31, w2, #4, #0x1f", 0x53047C5F, 0);
    addinstr("ubfm x4, x14, #4, #2", 0xD34409C4, 0);
    addinstr("ubfm x8, x1, #32, #24", 0xD3606028, 0);
    addinstr("ubfm w21, w13, #16, #8", 0x531021B5, 0);
    addinstr("ubfm x4, x12, #0, #7", 0xD3401D84, 0);
    addinstr("ubfm w5, w1, #0, #7", 0x53001C25, 0);
    addinstr("ubfm w0, w6, #5, #15", 0x53053CC0, 0);
    addinstr("ubfm x2, x20, #0, #15", 0xD3403E82, 0);
    addinstr("ubfm w3, w4, #0, #31", 0x53007C83, 0);
    addinstr("ubfm x19, x9, #0, #31", 0xD3407D33, 0);
    addinstr("ubfm w5, w9, #0, #15", 0x53003D25, 0);
    addinstr("ubfm x16, x13, #0, #15", 0xD3403DB0, 0);

	addinstr("extr x5, x2, x11, #3", 0x93CB0C45, 0);
    addinstr("extr w6, w8, w1, #25", 0x13816506, 0);
    addinstr("extr x20, x3, x3, #32", 0x93C38074, 0);
    addinstr("extr w1, w13, w13, #1", 0x138D05A1, 0);
	*/
	
	//addinstr("b #0x40 @ 0x100007f30", 0x14000010, 0x100007f30);
/*	addinstr("b.eq #0x50 @ 0x100007f28", 0x54000280, 0x100007f28);
	addinstr("b.ne #-0x880 @ 0x100007f2c", 0x54FFBC01, 0x100007f2c);
	addinstr("b.cs #0x90 @ 0x100007f30", 0x54000482, 0x100007f30);
	addinstr("b.cc #0x8290 @ 0x100007f34", 0x54041483, 0x100007f34);
	addinstr("b.al #0x3990 @ 0x100007f34", 0x5401CC8E, 0x100007f34);
*/

	/*addinstr("svc #40", 0xD4000501, 0);
	addinstr("smc #4", 0xD4000083, 0);
	addinstr("hvc #0", 0xD4000002, 0);*/

	/*addinstr("brk #4", 0xD4200080, 0);
	addinstr("hlt #80", 0xD4400A00, 0);
*/

/*	addinstr("dcps1 #4", 0xD4A00081, 0);
 *
 *	
	addinstr("dcps2 #8", 0xD4A00102, 0);
	addinstr("dcps3 #12", 0xD4A00183, 0);
*/

/*	addinstr("nop", 0xD503201F, 0);
	addinstr("yield", 0xD503203F, 0);
	addinstr("wfe", 0xD503205F, 0);
	addinstr("wfi", 0xD503207F, 0);
	addinstr("sev", 0xD503209F, 0);
	addinstr("sevl", 0xD50320BF, 0);
*/
	/*addinstr("xpaclri", 0xd50320ff, 0);
	addinstr("xpacd x5", 0xdac147e5, 0);
	addinstr("xpaci x19", 0xdac143f3, 0);
	*/

	
	/* 0x100007f2c      1f2103d5       pacia1716                  ; [00] -r-x section size 44 named 0.__TEXT.__text
|           0x100007f30      5f2103d5       pacib1716
|           0x100007f34      9f2103d5       autia1716
|           0x100007f38      df2103d5       autib1716 */

/*	addinstr("pacia1716", 0xd503211f, 0);
	addinstr("pacib1716", 0xd503215f, 0);
	addinstr("autia1716", 0xd503219f, 0);
	addinstr("autib1716", 0xd50321df, 0);
*/	
//1f2203d5       esb
//	addinstr("esb", 0xd503221f, 0);

/*
 *            0x100007f1c      1f2303d5       paciaz                     ; [00] -r-x section size 60 named 0.__TEXT.__text
|           0x100007f20      3f2303d5       paciasp
|           0x100007f24      5f2303d5       pacibz
|           0x100007f28      7f2303d5       pacibsp
|           0x100007f2c      9f2303d5       autiaz
|           0x100007f30      bf2303d5       autiasp
|           0x100007f34      df2303d5       autibz
|           0x100007f38      ff2303d5       autibsp
*/

/*	addinstr("paciaz", 0xd503231f, 0);
	addinstr("paciasp", 0xd503233f, 0);
	addinstr("pacibz", 0xd503235f, 0);
	addinstr("pacibsp", 0xd503237f, 0);
	addinstr("autiaz", 0xd503239f, 0);
	addinstr("autiasp", 0xd50323bf, 0);
	addinstr("autibz", 0xd50323df, 0);
	addinstr("autibsp", 0xd50323ff, 0);
*/

	
	//addinstr("clrex #5", 0xD503355F, 0);
	/*addinstr("dmb ish", 0xD5033BBF, 0);
	addinstr("dmb osh", 0xD50333BF, 0);
	addinstr("dmb sy", 0xD5033FBF, 0);
	addinstr("dmb oshld", 0xD50331BF, 0);
	addinstr("isb sy", 0xD5033FDF, 0);
	addinstr("isb #5", 0xD50335DF, 0);
	addinstr("dsb ish", 0xD5033B9F, 0);
	addinstr("dsb #8", 0xD503389F, 0);
	addinstr("msr SPSel, #3", 0xD50043BF, 0);


	addinstr("sys #3, C7, C1, #4, x0", 0xD50B7180, 0);	
	addinstr("at s1e1r, x0", 0xD5087800, 0);
	addinstr("tlbi IPAS2E1IS, x4", 0xD50C8024, 0);


	addinstr("ic ivau, x0", 0xD50B7520, 0);
	addinstr("ic iallu", 0xD508751F, 0);
	addinstr("dc CIVAC, x14", 0xD50B7E2E, 0);
	*/
	/*addinstr("sysl x4, #5, C4, C3, #4", 0xD52D4384, 0);
	addinstr("msr ACTLR_EL1, x5", 0xD5181025, 0);
	addinstr("msr DBGWCR5_EL1, x11", 0xD51005EB, 0);
	addinstr("mrs x23, DBGWCR5_EL1", 0xD53005F7, 0);
	addinstr("br x9", 0xD61F0120, 0);
	addinstr("braaz x22", 0xd61f0adf, 0);
	addinstr("brabz x13", 0xd61f0dbf, 0);
	*/
	/*
	 *   0x100007f30      20003fd6       blr x1
|           0x100007f34      9f083fd6       blraaz x4
|           0x100007f38      bf0c3fd6       blrabz x5

*/
/*
	addinstr("blr x1", 0xD63F0020, 0);
	addinstr("blraaz x4", 0xd63f089f, 0);
	addinstr("blrabz x5", 0xd63f0cbf, 0);
	addinstr("ret", 0xD65F03C0, 0);
	addinstr("retaa", 0xd65f0bff, 0);
	addinstr("retab", 0xd65f0fff, 0);
	addinstr("eret", 0xD69F03E0, 0);
	addinstr("eretaa", 0xd69f0bff, 0);
	addinstr("eretab", 0xd69f0fff, 0);
	addinstr("drps", 0xD6BF03E0, 0);
*/

	/*
	 *  0x100007f2c      39081fd7       braa x1, x25               ; [00] -r-x section size 44 named 0.__TEXT.__text
|           0x100007f30      9f081fd7       braa x4, sp
|           0x100007f34      c10c1fd7       brab x6, x1
|           0x100007f38      1f0d1fd7       brab x8, sp
*/
/*
	addinstr("braa x1, x25", 0xd71f0839, 0);
	addinstr("braa x4, sp", 0xd71f089f, 0);
	addinstr("brab x6, x1", 0xd71f0cc1, 0);
	addinstr("brab x8, sp", 0xd71f0d1f, 0);
*/
/*			0x100007f2c      39083fd7       blraa x1, x25              ; [00] -r-x section size 44 named 0.__TEXT.__text
|           0x100007f30      9f083fd7       blraa x4, sp
|           0x100007f34      c10c3fd7       blrab x6, x1
|           0x100007f38      1f0d3fd7       blrab x8, sp
*/
/*
	addinstr("blraa x1, x25", 0xd73f0839, 0);
	addinstr("blraa x4, sp", 0xd73f089f, 0);
	addinstr("blrab x6, x1", 0xd73f0cc1, 0);
	addinstr("blrab x8, sp", 0xd73f0d1f, 0);
*/
/*
 * :   0x100007f2c      70150014       b 0x10000d4ec              ; [00] -r-x section size 44 named 0.__TEXT.__text
|       `=< 0x100007f30      2bffff17       b 0x100007bdc
|           0x100007f34      12000094       bl 0x100007f7c
|           0x100007f38      40ffff97       bl 0x100007c38

*/

/*	addinstr("b 0x55c0 @ 0x100007f2c", 0x14001570, 0x100007f2c);
	addinstr("b -0x354 @ 0x100007f30", 0x17ffff2b, 0x100007f30);
	addinstr("bl 0x48 @ 0x100007f34", 0x94000012, 0x100007f34);
	addinstr("bl -0x300 @ 0x100007f38", 0x97ffff40, 0x100007f38);
*/
	/*
	 *  0x100007f2c      090200b4       cbz x9, 0x100007f6c        ; [00] -r-x section size 44 named 0.__TEXT.__text
|           0x100007f30      11e6ffb4       cbz x17, 0x100007bf0
|           0x100007f34      024800b5       cbnz x2, 0x100008834
|           0x100007f38      8dfdffb5       cbnz x13, 0x100007ee8
*/
/*	
	addinstr("cbz x9, #0x40 @ 0x100007f2c", 0xB4000209, 0x100007f2c);
	addinstr("cbz x17, -0x340 @ 0x100007f30", 0xb4ffe611, 0x100007f30);
	addinstr("cbnz x2, #0x900 @ 0x100007f34", 0xb5004802, 0x100007f34);
	addinstr("cbnz x13, -0x50 @ 0x100007f38", 0xB5FFFD8D, 0x100007f38);
*/
/*
 *  0x100007f2c      09800236       tbz w9, #0, 0x10000cf2c    ; [00] -r-x section size 44 named 0.__TEXT.__text
|           0x100007f30      11700e36       tbz w17, #1, 0x100004d30
|           0x100007f34      22000837       tbnz w2, #1, 0x100007f38
|           0x100007f38      2d200037       tbnz w13, #0, 0x10000833c
*/
/*
	addinstr("tbz x9, 0x0, 0x5000 @ 0x100007f2c", 0x36028009, 0x100007f2c);
	addinstr("tbz x17, 0x1, -0x3200 @ 0x100007f30", 0x360e7011, 0x100007f30);
	addinstr("tbnz x2, 0x1, 0x4 @ 0x100007f34", 0x37080022, 0x100007f34);
	addinstr("tbnz x13, 0x0, 0x404 @ 0x100007f38", 0x3700202d, 0x100007f38);
*/
	
/*	addinstr("st1 {v4.1d}, [x8]", 0x0C007D04, 0);
	addinstr("ld1 {v9.1d}, [x2]", 0x0C407C49, 0);
	addinstr("ld2 {v9.4s, v10.4s}, [x16]", 0x4C408A09, 0);
	addinstr("st2 {v4.4s, v5.4s}, [sp]", 0x4C008BE4, 0);
	addinstr("ld3 {v20.4h, v21.4h, v22.4h}, [x7]", 0x0C4044F4, 0);
	addinstr("st3 {v0.8b, v1.8b, v2.8b}, [sp]", 0x0C0043E0, 0);
	addinstr("ld4 {v13.8b, v14.8b, v15.8b, v16.8b}, [sp]", 0x0C4003ED, 0);
	addinstr("st4 {v4.16b, v5.16b, v6.16b, v7.16b}, [x14]", 0x4C0001C4, 0);
	addinstr("st3 {v0.8b, v1.8b, v2.8b}, [sp], x0", 0x0C8043E0, 0);
	addinstr("st3 {v22.8b, v23.8b, v24.8b}, [x16], #24", 0x0C9F4216, 0);
	addinstr("ld1 {v20.2s, v21.2s, v22.2s, v23.2s}, [x21], #32", 0x0CDF2AB4, 0);
	addinstr("st2 {v2.8h, v3.8h}, [x4], x16", 0x4C908482, 0);
	addinstr("st1 {v2.2s}, [sp], #8", 0x0C9F7BE2, 0);
*/
	addinstr("st1 {v4.b}[6], [x22]", 0x0D001AC4, 0);
	addinstr("st3 {v1.d, v2.d, v3.d}[0], [x5], #24", 0x0D9FA4A1, 0);
	addinstr("ld4 {v11.h, v12.h, v13.h, v14.h}[1], [sp], #8", 0x0DFF6BEB, 0);
	addinstr("ld2 {v22.s, v23.s}[3], [x3]", 0x4D609076, 0);

	struct node_t *current = instructions->front;

	while(current){
		struct testinstr *ti = (struct testinstr *)current->data;
		printf("Disassembling %s (aka 0x%08x)... ", ti->name, ti->hex);
		struct instruction *i = instruction_new(ti->hex, ti->PC);
		char *ret = ArmadilloDisassemble(i);
		//printf("ret = %p\n", ret);
		instruction_free(i);
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
