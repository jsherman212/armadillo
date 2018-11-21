#ifndef _DATAPROCESSINGIMMEDIATE_H_
#define _DATAPROCESSINGIMMEDIATE_H_

#include "bits.h"

char *DataProcessingImmediateDisassemble(unsigned int instruction);


static const char *ARM64_GeneralRegisters[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6",
	"x7", "x8", "x9", "x10", "x11", "x12",
	"x13", "x14", "x15", "x16", "x17", "x18",
	"x19", "x20", "x21", "x22", "x23", "x24",
	"x25", "x26", "x27", "x28", "fp", "lr", "sp" };

static const char *ARM64_32BitGeneralRegisters[] = {
	"w0", "w1", "w2", "w3", "w4", "w5", "w6",
	"w7", "w8", "w9", "w10", "w11", "w12",
	"w13", "w14", "w15", "w16", "w17", "w18",
	"w19", "w20", "w21", "w22", "w23", "w24",
	"w25", "w26", "w27", "w28", "fp", "lr", "wsp" };

#endif
