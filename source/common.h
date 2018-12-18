#ifndef _COMMON_H_
#define _COMMON_H_

static const char *ARM64_GeneralRegisters[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6",
	"x7", "x8", "x9", "x10", "x11", "x12",
	"x13", "x14", "x15", "x16", "x17", "x18",
	"x19", "x20", "x21", "x22", "x23", "x24",
	"x25", "x26", "x27", "x28", "fp", "lr", "xzr" };

static const char *ARM64_32BitGeneralRegisters[] = {
	"w0", "w1", "w2", "w3", "w4", "w5", "w6",
	"w7", "w8", "w9", "w10", "w11", "w12",
	"w13", "w14", "w15", "w16", "w17", "w18",
	"w19", "w20", "w21", "w22", "w23", "w24",
	"w25", "w26", "w27", "w28", "fp", "lr", "wzr" };

static const char *ARM64_VectorRegisters[] = {
	"v0", "v1", "v2", "v3", "v4", "v5", "v6",
	"v7", "v8", "v9", "v10", "v11", "v12",
	"v13", "v14", "v15", "v16", "v17", "v18",
	"v19", "v20", "v21", "v22", "v23", "v24",
	"v25", "v26", "v27", "v28", "v29", "v30", "v31" };

static const char *ARM64_VectorDoublePrecisionRegisters[] = {
	"d0", "d1", "d2", "d3", "d4", "d5", "d6",
	"d7", "d8", "d9", "d10", "d11", "d12",
	"d13", "d14", "d15", "d16", "d17", "d18",
	"d19", "d20", "d21", "d22", "d23", "d24",
	"d25", "d26", "d27", "d28", "d29", "d30", "d31" };

static const char *ARM64_VectorSinglePrecisionRegisters[] = {
	"s0", "s1", "s2", "s3", "s4", "s5", "s6",
	"s7", "s8", "s9", "s10", "s11", "s12",
	"s13", "s14", "s15", "s16", "s17", "s18",
	"s19", "s20", "s21", "s22", "s23", "s24",
	"s25", "s26", "s27", "s28", "s29", "s30", "s31" };

static const char *ARM64_VectorHalfPrecisionRegisters[] = {
	"h0", "h1", "h2", "h3", "h4", "h5", "h6",
	"h7", "h8", "h9", "h10", "h11", "h12",
	"h13", "h14", "h15", "h16", "h17", "h18",
	"h19", "h20", "h21", "h22", "h23", "h24",
	"h25", "h26", "h27", "h28", "h29", "h30", "h31" };


#endif
