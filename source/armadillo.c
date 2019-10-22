#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "armadillo.h"
#include "bits.h"
#include "instruction.h"
#include "strext.h"

#include "BranchExcSys.h"
#include "DataProcessingImmediate.h"
#include "DataProcessingFloatingPoint.h"
#include "DataProcessingRegister.h"
#include "LoadsAndStores.h"


char *_ArmadilloDisassemble(struct instruction *instr){
    unsigned int op0 = getbitsinrange(instr->opcode, 25, 4);

    char *disassembled = NULL;

    if(op0 == 0)
        return strdup(".undefined");
    else if(op0 == 1)
        return strdup(".undefined");
    else if((op0 & ~0x1) == 0x2)
        return strdup(".undefined");
    else if((op0 & ~0x1) == 0x8)
        disassembled = DataProcessingImmediateDisassemble(instr);
    else if((op0 & ~0x1) == 0xa)
        disassembled = BranchExcSysDisassemble(instr);
    else if((op0 & ~0xa) == 0x4)
        disassembled = LoadsAndStoresDisassemble(instr);
    else if((op0 & ~0x8) == 0x5)
        disassembled = DataProcessingRegisterDisassemble(instr);
    else if((op0 & ~0x8) == 0x7)
        disassembled = DataProcessingFloatingPointDisassemble(instr);
    else
        return strdup(".unknown");

    return disassembled;
}

unsigned int CFSwapInt32(unsigned int arg) {
    unsigned int result;
    result = ((arg & 0xFF) << 24) | ((arg & 0xFF00) << 8) |
        ((arg >> 8) & 0xFF00) | ((arg >> 24) & 0xFF);
    return result;
}

char *ArmadilloDisassemble(unsigned int opcode, unsigned long PC){
    struct instruction *instr = instruction_new(opcode, PC);
    char *disassembled = _ArmadilloDisassemble(instr);
    free(instr);
    return disassembled;
}

char *ArmadilloDisassembleB(unsigned int opcode, unsigned long PC){
    return ArmadilloDisassemble(CFSwapInt32(opcode), PC);
}

static int _ArmadilloDisassembleNew(struct instruction *i,
        struct ad_insn **_out){
    struct ad_insn *out = *_out;

    unsigned op0 = bits(i->opcode, 25, 28);

    if(op0 <= 3){
        concat(&out->decoded, ".long %#x", i->opcode);
        return AD_OK;
    }
    
    if((op0 & ~0x1) == 0x8)
        return DataProcessingImmediateDisassemble(i, out);

    return AD_OK;
}

int ArmadilloDisassembleNew(unsigned int opcode, unsigned long PC,
        struct ad_insn **out){
    // XXX *out must be NULL
    if(!out || (out && *out))
        return A_ERR;

    *out = malloc(sizeof(struct ad_insn));

    (*out)->decoded = NULL;

    (*out)->group = NONE;
    (*out)->instr_id = NONE;

    (*out)->fields = NULL;
    (*out)->num_fields = 0;

    (*out)->operands = NULL;
    (*out)->num_operands = 0;

    (*out)->cc = NONE;

    struct instruction *i = instruction_new(opcode, PC);

    int result = _ArmadilloDisassembleNew(i, out);

    free(i);

    return result;
}

int ArmadilloDone(struct ad_insn **_insn){
    if(!_insn)
        return AD_ERR;

    // XXX todo as I go along


    return AD_OK;
}
