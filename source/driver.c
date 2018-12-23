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

//addinstr("adrp x1, #0x10000a000 @ 0x10000a79c", 0x90000001, 0x10000a79c);

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
	/*
	addinstr("st1 {v4.1d}, [x8]", 0x0C007D04, 0);
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
	addinstr("st1 {v4.2s, v5.2s}, [x20]", 0x0C00AA84, 0);
*/

	/*
	addinstr("st1 {v4.b}[6], [x22]", 0x0D001AC4, 0);
	addinstr("st3 {v1.d, v2.d, v3.d}[0], [x5], #24", 0x0D9FA4A1, 0);
	addinstr("st3 {v11.d, v12.d, v13.d}[1], [x2], x4", 0x4D84A44B, 0);
	addinstr("ld4 {v11.h, v12.h, v13.h, v14.h}[1], [sp], #8", 0x0DFF6BEB, 0);
	addinstr("ld2 {v22.s, v23.s}[3], [x3]", 0x4D609076, 0);
	addinstr("ld4r {v20.2s, v21.2s, v22.2s, v23.2s}, [x21]", 0x0D60EAB4, 0);
	addinstr("ld1r {v2.4h}, [x2], #2", 0x0DDFC442, 0);
	addinstr("ld2r {v28.2s, v29.2s}, [sp], x20", 0x0DF4CBFC, 0);
	addinstr("ld3r {v15.2d, v16.2d, v17.2d}, [x1], #24", 0x4DDFEC2F, 0);
*/

	/*
	addinstr("stxrb w2, w4, [x3]", 0x08027C64, 0);
	addinstr("stlxrb w4, w22, [sp]", 0x0804FFF6, 0);
	addinstr("stxrh w24, w0, [x23]", 0x48187EE0, 0);
	addinstr("stlxrh w5, w3, [x12]", 0x4805FD83, 0);
	addinstr("stxr w13, w9, [sp]", 0x880D7FE9, 0);
	addinstr("stlxr w2, w28, [x14]", 0x8802FDDC, 0);
	addinstr("stlxr w2, x28, [x14]", 0xC802FDDC, 0);
	addinstr("stxp w3, w5, w2, [x4]", 0x88230885, 0);
	addinstr("stlxp w1, x15, x12, [x21]", 0xC821B2AF, 0);
	addinstr("ldxr x5, [x3]", 0xC85F7C65, 0);
	addinstr("ldxrh w2, [sp]", 0x485F7FE2, 0);
	addinstr("ldaxrh w10, [x3]", 0x485FFC6A, 0);
	addinstr("ldxp w13, w2, [x3]", 0x887F086D, 0);
	addinstr("stllr w2, [x3]", 0x889f7c62, 0);
	addinstr("ldlarb w3, [x4]", 0x08df7c83, 0);
	addinstr("caspa x6, x7, x2, x3, [x8]", 0x48667d02, 0);
	addinstr("caspal x6, x7, x2, x3, [x8]", 0x4866fd02, 0);
	addinstr("cash w5, w6, [x4]", 0x48a57c86, 0);
	addinstr("caslh w5, w6, [x4]", 0x48a5fc86, 0);
	addinstr("casah w5, w6, [x4]", 0x48e57c86, 0);
	addinstr("casalh w5, w6, [x4]", 0x48e5fc86, 0);
	addinstr("cas w5, w6, [x4]", 0x88a57c86, 0);
	addinstr("cas x5, x6, [x4]", 0xc8a57c86, 0);
	addinstr("casl x5, x6, [x4]", 0xc8a5fc86, 0);
*/
/*
	addinstr("ldr x4, #0x20 @ 0x100007f30", 0x58000104, 0x100007f30);
	addinstr("ldr x16, #-0x474 @ 0x100007f34", 0x58ffdc70, 0x100007f34);
	addinstr("ldr w2, #0x40000 @ 0x100007f38", 0x18200002, 0x100007f38);
	//addinstr("prfm    PLDL1STRM, [x1]", 0xF9800021, 0);
	addinstr("ldr s1, #0x344 @ 0x100007f24", 0x1c001a21, 0x100007f24);
	addinstr("ldr q13, #-0x400 @ 0x100007f28", 0x9cffe00d, 0x100007f28);
	addinstr("ldr d3, #0x90 @ 0x100007f2c", 0x5c000483, 0x100007f2c);
	addinstr("ldrsw x18, #0x78 @ 0x100007f20", 0x980003d2, 0x100007f20);
*/

	/*
	addinstr("stnp x2, x1, [x24, #-304]", 0xA82D0702, 0);
	addinstr("stnp w5, w2, [sp]", 0x28000BE5, 0);
	addinstr("ldnp q2, q3, [x3, #992]", 0xAC5F0C62, 0);
	addinstr("ldnp s22, s23, [x15, #-256]", 0x2C605DF6, 0);
	addinstr("ldpsw x1, x2, [x15, #32]", 0x694409E1, 0);
	addinstr("stp x6, x2, [x1], #32", 0xA8820826, 0);
	addinstr("stp d7, d22, [sp, #208]!", 0x6D8D5BE7, 0);
	addinstr("stp d7, d22, [sp, #-208]!", 0x6DB35BE7, 0);
	addinstr("ldp x16, x4, [x4, #24]", 0xA9419090, 0);
	*/

/*
	addinstr("sturb w3, [x5, #255]", 0x380FF0A3, 0);
	addinstr("sturb w16, [sp]", 0x380003F0, 0);
	addinstr("sturb w1, [x2, #-4]", 0x381FC041, 0);
	addinstr("ldursb w6, [x10]", 0x38C00146, 0);
	addinstr("ldursb w22, [x9, #26]", 0x38C1A136, 0);
	addinstr("stur h4, [x5]", 0x7C0000A4, 0);
	addinstr("stur s13, [sp]", 0xBC0003ED, 0);
	addinstr("stur d22, [x1, #4]", 0xFC004036, 0);
	addinstr("stur q3, [x12, #-40]", 0x3C9D8183, 0);
	addinstr("ldursw x0, [x4]", 0xB8800080, 0);
	addinstr("ldursh w3, [x14, #4]", 0x78C041C3, 0);
	addinstr("stur x5, [sp]", 0xF80003E5, 0);
	addinstr("stur w19, [x2, #10]", 0xB800A053, 0);
	addinstr("strb w8, [x8]", 0x39000108, 0);
	addinstr("strb w2, [x12], #4", 0x38004582, 0);
	addinstr("strb w13, [x0, #40]!", 0x38028C0D, 0);
	addinstr("ldrsb w1, [x5, #4]", 0x39C010A1, 0);
	addinstr("str h6, [x0, #34]", 0x7D004406, 0);
	addinstr("str x18, [x0, #0x340]", 0xF901A012, 0);
	addinstr("ldur s9, [x4, #-0x40]", 0xBC5C0089, 0);
	addinstr("ldr x24, [x5, #0x390]", 0xF941C8B8, 0);
	addinstr("ldtrsb x0, [x0]", 0x38800800, 0);
	addinstr("sttr x5, [x3, #0x30]", 0xF8030865, 0);
	addinstr("ldtrb w9, [x5, #1]", 0x384018A9, 0);
	addinstr("ldur h9, [x4, #-0x40]", 0x7C5C0089, 0);
	addinstr("ldur b9, [x4, #-0x40]", 0x3C5C0089, 0);
	addinstr("ldur d9, [x4, #-0x40]", 0xFC5C0089, 0);
	addinstr("ldur q9, [x4, #-0x40]", 0x3CDC0089, 0);
	addinstr("ldr x8, [x8, 0x120]", 0xf9409108, 0);
	addinstr("stp x29, x30, [sp, 0x70]", 0xa9077bfd, 0);
	addinstr("str w12, [x13, 0x1c]", 0xb9001dac, 0);
	addinstr("stur w8, [x29, -0x64]", 0xb819c3a8, 0);
	addinstr("str wzr, [x8, 0xc]", 0xb9000d1f, 0);
*/
		/*
	addinstr("ldaddab w9, w10, [x4]", 0x38a9008a, 0);
	addinstr("swpalh w5, w2, [sp]", 0x78e583e2, 0);
	addinstr("ldclr w20, w21, [x6]", 0xb83410d5, 0);
	addinstr("swpl x5, x4, [x21]", 0xf86582a4, 0);
	addinstr("ldapr w5, [sp]", 0xb8bfc3e5, 0);
	addinstr("ldaprb w19, [x3]", 0x38bfc073, 0);
	addinstr("ldaprh w1, [x19]", 0x78bfc261, 0);
*/

		/*
	addinstr("strb w4, [x4, w5, sxtw]", 0x3825C884, 0);
	addinstr("strb w1, [x4, x9, lsl #0]", 0x38297881, 0);
	addinstr("strb w1, [x4, x9]", 0x38296881, 0);
	addinstr("ldr b8, [sp, x4, sxtx]", 0x3C64EBE8, 0);
	addinstr("str h12, [x18, x3, lsl #1]", 0x7C237A4C, 0);
	addinstr("ldr s24, [sp, w14, sxtw]", 0xBC6ECBF8, 0);
	addinstr("ldr d16, [x9, w1, uxtw]", 0xFC614930, 0);
	addinstr("str x15, [x3, x18, lsl #3]", 0xF832786F, 0);
	addinstr("ldr w3, [x14, x8]", 0xB86869C3, 0);
	addinstr("ldr x1, [x14, x8, sxtx]", 0xF868E9C1, 0);
	addinstr("ldrsw x0, [sp, x3, sxtx #2]", 0xB8A3FBE0, 0);
	addinstr("ldrb w4, [x6, x20, lsl #0]", 0x387478C4, 0);
	addinstr("str q3, [x6, x4, sxtx #4]", 0x3CA4F8C3, 0);
	addinstr("str b8, [x15, x1, lsl #0]", 0x3C2179E8, 0);
	addinstr("str b13, [x0, x20]", 0x3C34680D, 0);
	*/

	/*addinstr("ldraa x9, [x2, #0x308]", 0xf8261449, 0);
	addinstr("ldraa x21, [sp, #-0x8]!", 0xf87ffff5, 0);
	addinstr("ldrab x1, [x5, #0xa0]", 0xf8a144a1, 0);
	addinstr("ldrab x14, [x19, #0x10]!", 0xf8a02e6e, 0);
	*/
	//addinstr("ldnp d1, d27, [x19, -0x1c0]", 0x6c646e61, 0);
	
	/*addinstr("pacga x4, x2, x20", 0x9ad43044, 0);
	addinstr("crc32cw w4, w2, w4", 0x1AC45844, 0);
	addinstr("pacga x13, x22, sp", 0x9adf32cd, 0);
	addinstr("rorv x3, x1, x20", 0x9AD42C23, 0);
	addinstr("sdiv w1, w2, w3", 0x1AC30C41, 0);
*/
/*
	addinstr("rbit w4, w2", 0x5AC00044, 0);
	addinstr("cls w13, w1", 0x5AC0142D, 0);
	addinstr("rev32 x4, x3", 0xDAC00864, 0);
	addinstr("rev w2, w3", 0x5AC00862, 0);
	addinstr("rev16 x20, x10", 0xDAC00554, 0);
	addinstr("rev x3, x6", 0xDAC00CC3, 0);
	addinstr("pacia x5, sp", 0xdac103e5, 0);
	addinstr("pacdb x13, x4", 0xdac10c8d, 0);
	addinstr("autib x11, x0", 0xdac1140b, 0);
	addinstr("autdb x0, sp", 0xdac11fe0, 0);
	addinstr("paciza xzr", 0xdac123ff, 0);
	addinstr("pacdzb x4", 0xdac12fe4, 0);
	addinstr("xpaci x9", 0xdac143e9, 0);
	addinstr("autdza x22", 0xdac13bf6, 0);
*/

		/*
	addinstr("and w2, w3, w1", 0x0A010062, 0);
	addinstr("bic x3, x13, x1, lsr #5", 0x8A6115A3, 0);
	addinstr("orr x3, x2, x1, ror #4", 0xAAC11043, 0);
	addinstr("orr x15, xzr, x3", 0xAA0303EF, 0);
	addinstr("orn w13, wzr, w4", 0x2A2403ED, 0);
	addinstr("eor x4, x2, x9", 0xCA090044, 0);
	addinstr("eon w4, w5, w6, asr #2", 0x4AA608A4, 0);
	addinstr("ands x4, x1, x2", 0xEA020024, 0);
	addinstr("ands wzr, w13, w21", 0x6A1501BF, 0);
	addinstr("bics x15, x13, x9", 0xEA2901AF, 0);
	addinstr("orn x2, xzr, x14, asr #43", 0xAAAEAFE2, 0);
	*/
	
	addinstr("add x4, x2, x1", 0x8B010044, 0);
	addinstr("add x15, x3, x2, lsr #21", 0x8B42546F, 0);
	addinstr("adds w4, w5, w6", 0x2B0600A4, 0);
	addinstr("adds x0, x20, x10, asr #60", 0xAB8AF280, 0);
	addinstr("adds xzr, x13, x1, lsl #4", 0xAB0111BF, 0);
	addinstr("sub w10, w1, w2", 0x4B02002A, 0);
	addinstr("sub w13, wzr, w14", 0x4B0E03ED, 0);
	addinstr("subs x5, x4, x3, lsl #4", 0xEB031085, 0);
	addinstr("subs xzr, x14, x2", 0xEB0201DF, 0);
	addinstr("subs x27, xzr, x1, lsr #44", 0xEB41B3FB, 0);



	

	struct node_t *current = instructions->front;

	while(current){
		struct testinstr *ti = (struct testinstr *)current->data;
		printf("Disassembling %s (aka 0x%08x)... ", ti->name, ti->hex);
		struct instruction *i = instruction_new(ti->hex, ti->PC);
		char *ret = _ArmadilloDisassemble(i);
		//printf("ret = %p\n", ret);
		instruction_free(i);
		printf("Disassembled: %s\n\n", ret);
 		free(ret);

		current = current->next;
	}

	linkedlist_free(instructions);

	return 0;
}
