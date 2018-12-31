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

	addinstr("adrp x1, #0x10000a000 @ 0x10000a79c", 0x90000001, 0x10000a79c);

	addinstr("mov x7, x4", 0xAA0403E7, 0);
	addinstr("add x0, x0, x1", 0x8B010000, 0);
	addinstr("add x0, x0, #0xfe", 0x9103F800, 0);
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
	
	
	addinstr("b #0x40 @ 0x100007f30", 0x14000010, 0x100007f30);
	addinstr("b.eq #0x50 @ 0x100007f28", 0x54000280, 0x100007f28);
	addinstr("b.ne #-0x880 @ 0x100007f2c", 0x54FFBC01, 0x100007f2c);
	addinstr("b.cs #0x90 @ 0x100007f30", 0x54000482, 0x100007f30);
	addinstr("b.cc #0x8290 @ 0x100007f34", 0x54041483, 0x100007f34);
	addinstr("b.al #0x3990 @ 0x100007f34", 0x5401CC8E, 0x100007f34);

	addinstr("svc #40", 0xD4000501, 0);
	addinstr("smc #4", 0xD4000083, 0);
	addinstr("hvc #0", 0xD4000002, 0);

	addinstr("brk #4", 0xD4200080, 0);
	addinstr("hlt #80", 0xD4400A00, 0);
	
	addinstr("dcps2 #8", 0xD4A00102, 0);
	addinstr("dcps3 #12", 0xD4A00183, 0);


	addinstr("nop", 0xD503201F, 0);
	addinstr("yield", 0xD503203F, 0);
	addinstr("wfe", 0xD503205F, 0);
	addinstr("wfi", 0xD503207F, 0);
	addinstr("sev", 0xD503209F, 0);
	addinstr("sevl", 0xD50320BF, 0);

	addinstr("xpaclri", 0xd50320ff, 0);
	addinstr("xpacd x5", 0xdac147e5, 0);
	addinstr("xpaci x19", 0xdac143f3, 0);

	addinstr("pacia1716", 0xd503211f, 0);
	addinstr("pacib1716", 0xd503215f, 0);
	addinstr("autia1716", 0xd503219f, 0);
	addinstr("autib1716", 0xd50321df, 0);
	
	addinstr("paciaz", 0xd503231f, 0);
	addinstr("paciasp", 0xd503233f, 0);
	addinstr("pacibz", 0xd503235f, 0);
	addinstr("pacibsp", 0xd503237f, 0);
	addinstr("autiaz", 0xd503239f, 0);
	addinstr("autiasp", 0xd50323bf, 0);
	addinstr("autibz", 0xd50323df, 0);
	addinstr("autibsp", 0xd50323ff, 0);
	
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
	
	addinstr("msr ACTLR_EL1, x5", 0xD5181025, 0);
	addinstr("msr DBGWCR5_EL1, x11", 0xD51005EB, 0);
	addinstr("mrs x23, DBGWCR5_EL1", 0xD53005F7, 0);
	addinstr("br x9", 0xD61F0120, 0);
	addinstr("braaz x22", 0xd61f0adf, 0);
	addinstr("brabz x13", 0xd61f0dbf, 0);
	
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
	
	addinstr("braa x1, x25", 0xd71f0839, 0);
	addinstr("braa x4, sp", 0xd71f089f, 0);
	addinstr("brab x6, x1", 0xd71f0cc1, 0);
	addinstr("brab x8, sp", 0xd71f0d1f, 0);
	
	addinstr("blraa x1, x25", 0xd73f0839, 0);
	addinstr("blraa x4, sp", 0xd73f089f, 0);
	addinstr("blrab x6, x1", 0xd73f0cc1, 0);
	addinstr("blrab x8, sp", 0xd73f0d1f, 0);

	addinstr("b 0x55c0 @ 0x100007f2c", 0x14001570, 0x100007f2c);
	addinstr("b -0x354 @ 0x100007f30", 0x17ffff2b, 0x100007f30);
	addinstr("bl 0x48 @ 0x100007f34", 0x94000012, 0x100007f34);
	addinstr("bl -0x300 @ 0x100007f38", 0x97ffff40, 0x100007f38);
	
	addinstr("cbz x9, #0x40 @ 0x100007f2c", 0xB4000209, 0x100007f2c);
	addinstr("cbz x17, -0x340 @ 0x100007f30", 0xb4ffe611, 0x100007f30);
	addinstr("cbnz x2, #0x900 @ 0x100007f34", 0xb5004802, 0x100007f34);
	addinstr("cbnz x13, -0x50 @ 0x100007f38", 0xB5FFFD8D, 0x100007f38);
	
	addinstr("tbz x9, 0x0, 0x5000 @ 0x100007f2c", 0x36028009, 0x100007f2c);
	addinstr("tbz x17, 0x1, -0x3200 @ 0x100007f30", 0x360e7011, 0x100007f30);
	addinstr("tbnz x2, 0x1, 0x4 @ 0x100007f34", 0x37080022, 0x100007f34);
	addinstr("tbnz x13, 0x0, 0x404 @ 0x100007f38", 0x3700202d, 0x100007f38);
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

	addinstr("st1 {v4.b}[6], [x22]", 0x0D001AC4, 0);
	addinstr("st3 {v1.d, v2.d, v3.d}[0], [x5], #24", 0x0D9FA4A1, 0);
	addinstr("st3 {v11.d, v12.d, v13.d}[1], [x2], x4", 0x4D84A44B, 0);
	addinstr("ld4 {v11.h, v12.h, v13.h, v14.h}[1], [sp], #8", 0x0DFF6BEB, 0);
	addinstr("ld2 {v22.s, v23.s}[3], [x3]", 0x4D609076, 0);
	addinstr("ld4r {v20.2s, v21.2s, v22.2s, v23.2s}, [x21]", 0x0D60EAB4, 0);
	addinstr("ld1r {v2.4h}, [x2], #2", 0x0DDFC442, 0);
	addinstr("ld2r {v28.2s, v29.2s}, [sp], x20", 0x0DF4CBFC, 0);
	addinstr("ld3r {v15.2d, v16.2d, v17.2d}, [x1], #24", 0x4DDFEC2F, 0);

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

	addinstr("ldr x4, #0x20 @ 0x100007f30", 0x58000104, 0x100007f30);
	addinstr("ldr x16, #-0x474 @ 0x100007f34", 0x58ffdc70, 0x100007f34);
	addinstr("ldr w2, #0x40000 @ 0x100007f38", 0x18200002, 0x100007f38);
	//addinstr("prfm    PLDL1STRM, [x1]", 0xF9800021, 0);
	addinstr("ldr s1, #0x344 @ 0x100007f24", 0x1c001a21, 0x100007f24);
	addinstr("ldr q13, #-0x400 @ 0x100007f28", 0x9cffe00d, 0x100007f28);
	addinstr("ldr d3, #0x90 @ 0x100007f2c", 0x5c000483, 0x100007f2c);
	addinstr("ldrsw x18, #0x78 @ 0x100007f20", 0x980003d2, 0x100007f20);

	addinstr("stnp x2, x1, [x24, #-304]", 0xA82D0702, 0);
	addinstr("stnp w5, w2, [sp]", 0x28000BE5, 0);
	addinstr("ldnp q2, q3, [x3, #992]", 0xAC5F0C62, 0);
	addinstr("ldnp s22, s23, [x15, #-256]", 0x2C605DF6, 0);
	addinstr("ldpsw x1, x2, [x15, #32]", 0x694409E1, 0);
	addinstr("stp x6, x2, [x1], #32", 0xA8820826, 0);
	addinstr("stp d7, d22, [sp, #208]!", 0x6D8D5BE7, 0);
	addinstr("stp d7, d22, [sp, #-208]!", 0x6DB35BE7, 0);
	addinstr("ldp x16, x4, [x4, #24]", 0xA9419090, 0);
	
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
	
	addinstr("ldaddab w9, w10, [x4]", 0x38a9008a, 0);
	addinstr("swpalh w5, w2, [sp]", 0x78e583e2, 0);
	addinstr("ldclr w20, w21, [x6]", 0xb83410d5, 0);
	addinstr("swpl x5, x4, [x21]", 0xf86582a4, 0);
	addinstr("ldapr w5, [sp]", 0xb8bfc3e5, 0);
	addinstr("ldaprb w19, [x3]", 0x38bfc073, 0);
	addinstr("ldaprh w1, [x19]", 0x78bfc261, 0);

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

	addinstr("ldraa x9, [x2, #0x308]", 0xf8261449, 0);
	addinstr("ldraa x21, [sp, #-0x8]!", 0xf87ffff5, 0);
	addinstr("ldrab x1, [x5, #0xa0]", 0xf8a144a1, 0);
	addinstr("ldrab x14, [x19, #0x10]!", 0xf8a02e6e, 0);
	
	addinstr("ldnp d1, d27, [x19, -0x1c0]", 0x6c646e61, 0);
	*/
	/*addinstr("pacga x4, x2, x20", 0x9ad43044, 0);
	addinstr("crc32cw w4, w2, w4", 0x1AC45844, 0);
	addinstr("pacga x13, x22, sp", 0x9adf32cd, 0);
	addinstr("rorv x3, x1, x20", 0x9AD42C23, 0);
	addinstr("sdiv w1, w2, w3", 0x1AC30C41, 0);
	
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

	addinstr("add x4, sp, w3, lsl #0", 0x8B2363E4, 0);
	addinstr("add wsp, w4, w2, uxth #4", 0x0B22309F, 0);
	addinstr("add x21, x4, w2, sxtb #2", 0x8B228895, 0);
	
	// should simplify to add sp, x4, x5
	addinstr("add sp, x4, x5, lsl #0", 0x8B25609F, 0);
	addinstr("add x4, x12, x2, lsl #0", 0x8B020184, 0);
	addinstr("adds w3, w1, w5, sxth #3", 0x2B25AC23, 0);
	addinstr("adds xzr, sp, x3, lsl #4", 0xAB2373FF, 0);
	addinstr("adds x2, sp, x3, uxtx #4", 0xAB2373E2, 0);
	addinstr("sub x3, x4, w2, lsl #4", 0xCB227083, 0);
	addinstr("sub wsp, wsp, w4, lsl #0", 0x4B2443FF, 0);
	addinstr("sub x12, x1, x3, sxtx #2", 0xCB23E82C, 0);
	addinstr("sub sp, x4, x2, lsl #4", 0xCB22709F, 0);
	addinstr("subs x3, sp, w2, lsl #0", 0xEB2243E3, 0);
	addinstr("subs x20, x21, x1, uxtx #2", 0xEB216AB4, 0);
	addinstr("subs x4, x2, x2, lsl #0", 0xEB020044, 0);
	addinstr("subs xzr, x3, x12, lsl #0", 0xEB0C007F, 0);
	addinstr("subs xzr, x3, x12, lsl #3", 0xEB0C0C7F, 0);
	addinstr("sub x4, sp, w3, lsl #0", 0xCB2363E4, 0);
	
	addinstr("sbcs x4, xzr, x5", 0xFA0503E4, 0);
	addinstr("adc w3, w2, w1", 0x1A010043, 0);
	addinstr("sbcs x4, x14, x3", 0xFA0301C4, 0);

	addinstr("ccmn x4, x2, #4, ne", 0xBA421084, 0);
	addinstr("ccmp w1, w2, #13, pl", 0x7A42502D, 0);
	addinstr("ccmn x12, #3, #4, eq", 0xBA430984, 0);
	addinstr("ccmp w1, #15, #0, cc", 0x7A4F3820, 0);
	
	addinstr("csel w3, w5, w8, ne", 0x1A8810A3, 0);
	addinstr("csinc x4, x2, x5, pl", 0x9A855444, 0);
	addinstr("csinc x20, x4, x4, eq", 0x9A840494, 0);
	addinstr("csinc w4, wzr, wzr, cc", 0x1A9F37E4, 0);
	addinstr("csinv x4, x2, x1, ge", 0xDA81A044, 0);
	addinstr("csinv w14, w12, w12, hi", 0x5A8C818E, 0);
	addinstr("csinv w0, wzr, wzr, ls", 0x5A9F93E0, 0);
	addinstr("csneg x14, x15, x16, vs", 0xDA9065EE, 0);
	addinstr("csneg x3, x20, x20, ne", 0xDA941683, 0);
	
	addinstr("madd w3, w2, w1, w0", 0x1B010043, 0);
	addinstr("madd x4, x3, x2, xzr", 0x9B027C64, 0);
	addinstr("msub x7, x2, x12, x5", 0x9B0C9447, 0);
	addinstr("msub w3, w4, w1, wzr", 0x1B01FC83, 0);
	addinstr("smaddl x4, w3, w1, x7", 0x9B211C64, 0);
	addinstr("smaddl x14, w5, w12, xzr", 0x9B2C7CAE, 0);
	addinstr("smsubl x4, w15, w17, x2", 0x9B3189E4, 0);
	addinstr("smsubl x4, w15, w17, xzr", 0x9B31FDE4, 0);
	addinstr("smulh x4, x3, x1", 0x9B417C64, 0);
	addinstr("umaddl x14, w5, w12, x2", 0x9BAC08AE, 0);
	addinstr("umaddl x14, w5, w12, xzr", 0x9BAC7CAE, 0);
	addinstr("umsubl x14, w5, w12, x6", 0x9BAC98AE, 0);
	addinstr("umsubl x14, w5, w12, xzr", 0x9BACFCAE, 0);
	addinstr("umulh x4, x3, x2", 0x9BC27C64, 0);
	*/
	/*addinstr("aese v4.16b, v3.16b", 0x4e284864, 0);
	addinstr("aesd v6.16b, v4.16b", 0x4e285886, 0);
	addinstr("aesmc v20.16b, v11.16b", 0x4e286974, 0);
	addinstr("aesimc v7.16b, v16.16b", 0x4e287a07, 0);
	
	addinstr("sha1c q3, s4, v12.4s", 0x5e0c0083, 0);
	addinstr("sha256su1 v3.4s, v5.4s, v9.4s", 0x5e0960a3, 0);
	addinstr("sha256h q2, q3, v5.4s", 0x5e054062, 0);
	
	addinstr("sha1h s4, s5", 0x5e2808a4, 0);
	addinstr("sha1su1 v6.4s, v1.4s", 0x5e281826, 0);
	addinstr("sha256su0 v19.4s, v8.4s", 0x5e282913, 0);


	addinstr("mov h0, v0.h[0]", 0x5e020400, 0);
	addinstr("mov d25, v13.d[1]", 0x5e1805b9, 0);
	addinstr("mov b13, v8.b[2]", 0x5e05050d, 0);
	addinstr("mov s2, v19.s[3]", 0x5e1c0662, 0);
	

	
	addinstr("fmulx h4, h5, h6", 0x5e461ca4, 0);
	addinstr("fcmeq h2, h3, h1", 0x5e412462, 0);
	addinstr("frecps h20, h19, h2", 0x5e423e74, 0);
	addinstr("frsqrts h3, h4, h5", 0x5ec53c83, 0);
	addinstr("fcmge h3, h2, h1", 0x7e412443, 0);
	addinstr("facge h5, h3, h7", 0x7e472c65, 0);
	addinstr("facgt h3, h4, h5", 0x7ec52c83, 0);
	addinstr("fmaxnm v5.4h, v6.4h, v7.4h", 0x0e4704c5, 0);
	addinstr("fabd v20.8h, v4.8h, v6.8h", 0x6ec61494, 0);
	addinstr("sqrdmlah s4, s3, s2", 0x7e828464, 0);
	addinstr("fcmla v5.4h, v6.4h, v7.4h, #270", 0x2e47dcc5, 0);
	addinstr("fcmla v5.4h, v6.4h, v7.4h, #0", 0x2e47c4c5, 0);
	addinstr("fcmla v5.4h, v6.4h, v7.4h, #90", 0x2e47ccc5, 0);
	addinstr("fcmla v5.4h, v6.4h, v7.4h, #180", 0x2e47d4c5, 0);
	

	addinstr("sqadd s4, s3, s2", 0x5EA20C64, 0);
	addinstr("sshl v4.8b, v5.8b, v6.8b", 0x0E2644A4, 0);
	addinstr("cmtst d2, d0, d1", 0x5ee18c02, 0);
	addinstr("fcmeq s3, s4, s2", 0x5e22e483, 0);
	addinstr("smax v5.8b, v4.8b, v3.8b", 0x0e236485, 0);
	addinstr("bic v4.8b, v5.8b, v9.8b", 0x0e691ca4, 0);
	addinstr("eor v10.16b, v15.16b, v17.16b", 0x6e311dea, 0);
	addinstr("ushl v19.8h, v7.8h, v4.8h", 0x6e6444f3, 0);
	addinstr("addp v10.4s, v15.4s, v16.4s", 0x4eb0bdea, 0);
	addinstr("sqadd v0.16b, v1.16b, v2.16b", 0x4e220c20, 0);
	addinstr("fminnmp v0.2s, v1.2s, v2.2s", 0x2ea2c420, 0);
	addinstr("cmge v6.8b, v7.8b, v8.8b", 0x0e283ce6, 0);
	addinstr("uqshl v0.8h, v0.8h, v0.8h", 0x6e604c00, 0);
	

	addinstr("fcvtns h4, h6", 0x5e79a8c4, 0);
	addinstr("fcmge h4, h3, 0.0", 0x7ef8c864, 0);
	addinstr("ucvtf h10, h11", 0x7e79d96a, 0);
	addinstr("frsqrte h11, h12", 0x7ef9d98b, 0);
	
	addinstr("fcmgt s4, s5, 0.0", 0x5ea0c8a4, 0);
	addinstr("fcmgt h4, h3, 0.0", 0x5ef8c864, 0);
	addinstr("suqadd s4, s5", 0x5EA038A4, 0);
	addinstr("sqxtn b0, h0", 0x5e214800, 0);
	addinstr("rev64 v4.2s, v3.2s", 0x0ea00864, 0);
	addinstr("rev32 v15.8h, v16.8h", 0x6e600a0f, 0);
	addinstr("frintn v14.4h, v16.4h", 0x0e798a0e, 0);
	addinstr("sqxtun v3.4h, v6.4s", 0x2e6128c3, 0);
	addinstr("rbit v0.8b, v1.8b", 0x2e605820, 0);
	addinstr("ursqrte v6.2s, v5.2s", 0x2ea1c8a6, 0);
	
	addinstr("sqdmlal s1, h2, h4", 0x5e649041, 0);
	addinstr("pmull2 v6.1q, v7.2d, v4.2d", 0x4ee4e0e6, 0);
	addinstr("umlsl v0.4s, v1.4h, v2.4h", 0x2e62a020, 0);
	addinstr("sqdmull s4, h6, h8", 0x5e68d0c4, 0);
	addinstr("rsubhn v20.8b, v14.8h, v7.8h", 0x2e2761d4, 0);
	
	addinstr("sshr d6, d7, #2", 0x5f7e04e6, 0);
	//addinstr("sshr v4.4s, v4.4s, #2", 0x4f3e0484, 0);
	addinstr("sqshlu s5, s6, #4", 0x7f2464c5, 0);
	//addinstr("sri v8.16b, v9.16b, #6", 0x6f0a4528, 0);
	addinstr("sqshrn2 v10.8h, v4.4s, #5", 0x4f1b948a, 0);
	addinstr("fcvtzs v19.2s, v9.2s, #32", 0x0f20fd33, 0);
	addinstr("uqshrn b8, h9, #1", 0x7f0f9528, 0);
	
	addinstr("movi v6.8b, 0x4", 0x0f00e486, 0);
	addinstr("movi d5, 0xffffffffffffffff", 0x2f07e7e5, 0);
	addinstr("movi v10.2s, 0x8, lsl #16", 0x0f00450a, 0);
	addinstr("movi v1.4s, 0x20, msl #8", 0x4f01c401, 0);
	addinstr("movi d5, 0xffff000000000000", 0x2f06e405, 0);
	addinstr("orr v0.4h, 0x40, lsl #8", 0x0f02b400, 0);
	addinstr("orr v7.4s, 0x90, lsl #24", 0x4f047607, 0);
	addinstr("mvni v16.4s, 0x50, msl #16", 0x6f02d610, 0);
	addinstr("bic v19.2s, 0xff", 0x2f0717f3, 0);
	addinstr("bic v20.8h, 0x5", 0x6f0094b4, 0);
	addinstr("fmov v3.4h, #31.0", 0x0f01ffe3, 0);
	addinstr("fmov v5.2s, #25.0", 0x0f01f725, 0);
	addinstr("fmov v6.2d, #-3.0", 0x6f04f506, 0);
	
	addinstr("smlal v6.4s, v9.4h, v3.h[3]", 0x0f732126, 0);
	addinstr("fmla h9, h3, v9.h[7]", 0x5f391869, 0);
	addinstr("fmls v10.2s, v2.2s, v8.s[0]", 0x0f88504a, 0);
	addinstr("sqrdmlah h4, h5, v4.h[6]", 0x7f64d8a4, 0);
	addinstr("fcmla v5.4h, v6.4h, v7.h[0], #180", 0x2f4750c5, 0);
	
	addinstr("addp d3, v8.2d", 0x5ef1b903, 0);
	addinstr("fmaxp h2, v9.2h", 0x5e30f922, 0);
	addinstr("fminp h18, v20.2h", 0x5eb0fa92, 0);
	addinstr("fmaxnmp s0, v2.2s", 0x7e30c840, 0);
	addinstr("fminnmp d5, v4.2d", 0x7ef0c885, 0);
	
	addinstr("tbl v0.8b, {v8.16b, v9.16b, v10.16b}, v4.8b", 0x0e044100, 0);
	addinstr("tbl v5.16b, {v9.16b, v10.16b}, v9.16b", 0x4e092125, 0);
	addinstr("tbx v20.8b, {v3.16b, v4.16b, v5.16b, v6.16b}, v13.8b", 0x0e0d7074, 0);
	addinstr("tbx v7.16b, {v9.16b}, v20.16b", 0x4e141127, 0);

	addinstr("uzp1 v8.16b, v9.16b, v10.16b", 0x4e0a1928, 0);
	addinstr("trn2 v10.2s, v6.2s, v19.2s", 0x0e9368ca, 0);
	addinstr("zip1 v15.4h, v10.4h, v6.4h", 0x0e46394f, 0);


	addinstr("ext v5.8b, v3.8b, v9.8b, #5", 0x2e092865, 0);	
	
	addinstr("dup v8.8b, v6.b[3]", 0x0e0704c8, 0);
	addinstr("dup v5.2d, x5", 0x4e080ca5, 0);
	addinstr("dup v9.8h, w3", 0x4e020c69, 0);
	addinstr("smov w4, v9.b[0]", 0x0e012d24, 0);
	addinstr("smov x5, v0.h[5]", 0x4e162c05, 0);
	addinstr("umov w4, v5.h[4]", 0x0e123ca4, 0);
	addinstr("umov x3, v10.d[1]", 0x4e183d43, 0);
	addinstr("ins v9.b[0], w3", 0x4e011c69, 0);
	addinstr("ins v10.h[2], v9.h[1]", 0x6e0a152a, 0);
	
	
	addinstr("saddlv s5, v3.4h", 0x0e703865, 0);
	addinstr("sminv h2, v9.8h", 0x4e71a922, 0);
	addinstr("fmaxnmv h12, v8.4h", 0x0e30c90c, 0);
	addinstr("fminv h7, v2.8h", 0x4eb0f847, 0);
	addinstr("umaxv b20, v5.8b", 0x2e30a8b4, 0);
	addinstr("fminnmv s4, v7.4s", 0x6eb0c8e4, 0);
	

	
	addinstr("scvtf h6, w3, #2", 0x1ec2f866, 0);
	addinstr("scvtf s10, x14, #50", 0x9e0239ca, 0);
	addinstr("ucvtf s0, w2, #14", 0x1e03c840, 0);
	addinstr("ucvtf d7, w15, #1", 0x1e43fde7, 0);
	addinstr("fcvtzs x20, d4, #64", 0x9e580094, 0);
	addinstr("fcvtzs w4, h6, #10", 0x1ed8d8c4, 0);
	addinstr("fcvtzu w19, s7, #16", 0x1e19c0f3, 0);
	addinstr("fcvtzu x2, h0, #5", 0x9ed9ec02, 0);
	
	
	
	addinstr("fcvtns x4, h5", 0x9ee000a4, 0);
	addinstr("fcvtns w2, d10", 0x1e600142, 0);
	addinstr("fcvtnu x10, d7", 0x9e6100ea, 0);
	addinstr("scvtf s10, w1", 0x1e22002a, 0);
	addinstr("ucvtf h18, w14", 0x1ee301d2, 0);
	addinstr("fmov v4.d[1], x9", 0x9eaf0124, 0);
	addinstr("fmov s2, w5", 0x1e2700a2, 0);
	addinstr("fmov x9, v10.d[1]", 0x9eae0149, 0);
	addinstr("fcvtas w0, h0", 0x1ee40000, 0);
	addinstr("fcvtps x8, h1", 0x9ee80028, 0);
	addinstr("fjcvtzs w10, d4", 0x1e7e008a, 0);
	addinstr("fcvtzu x19, h6", 0x9ef900d3, 0);
	
	
	addinstr("fsqrt s4, s5", 0x1e21c0a4, 0);
	addinstr("fabs d10, d0", 0x1e60c00a, 0);
	addinstr("fcvt h9, s2", 0x1e23c049, 0);
	addinstr("frintp d5, d4", 0x1e64c085, 0);
	addinstr("fcvt s10, h3", 0x1ee2406a, 0);
	addinstr("frinti h9, h8", 0x1ee7c109, 0);
	
	
	
	addinstr("fcmp h9, h1", 0x1ee12120, 0);
	addinstr("fcmp s5, 0.0", 0x1e2020a8, 0);
	addinstr("fcmp d10, d2", 0x1e622140, 0);
	addinstr("fcmpe s10, s9", 0x1e292150, 0);
	addinstr("fcmpe d0, 0.0", 0x1e602018, 0);
	addinstr("fcmpe h6, 0.0", 0x1ee020d8, 0);
	

	
	addinstr("fmov s0, #5.0", 0x1E229000, 0);
	addinstr("fmov s9, #0.0", 0x1E2703E9, 0);
	addinstr("fmov s4, #-1.0", 0x1E3E1004, 0);
	addinstr("fmov s20, #0.5", 0x1E2C1014, 0);
	addinstr("fmov s7, #-0.5", 0x1E3C1007, 0);
	addinstr("fmov s18, #31.0", 0x1E27F012, 0);
	addinstr("fmov s12, #-26.0", 0x1E37500C, 0);
	addinstr("fmov h4, #5.0", 0x1ee29004, 0);
	addinstr("fmov h20, #14.0", 0x1ee59014, 0);
	addinstr("fmov h6, #-9.0", 0x1ef45006, 0);
	addinstr("fmov d4, #25.0", 0x1E673004, 0);
	addinstr("fmov d2, #0.0", 0x9E6703E2, 0);
	addinstr("fmov d10, #-9.0", 0x1E74500A, 0);
	addinstr("fmov d10, #31.0", 0x1E67F00A, 0);
	addinstr("fmov d7, #-19.0", 0x1E767007, 0);
	


	addinstr("fccmpe d5, d6, 0x4, ne", 0x1e6614b4, 0);
	addinstr("fccmp s0, s1, 0x0, le", 0x1e21d400, 0);
	

	addinstr("fmul s5, s3, s2", 0x1E220865, 0);
	addinstr("fminnm d5, d4, d3", 0x1e637885, 0);
	addinstr("fsub s9, s4, s14", 0x1e2e3889, 0);

	addinstr("fcsel d5, d14, d3, ne", 0x1e631dc5, 0);
	addinstr("fmsub d4, d23, d9, d2", 0x1f498ae4, 0);
	*/
	struct node_t *current = instructions->front;

	while(current){
		struct testinstr *ti = (struct testinstr *)current->data;
		printf("Disassembling %s (aka 0x%08x)...\n", ti->name, ti->hex);
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
