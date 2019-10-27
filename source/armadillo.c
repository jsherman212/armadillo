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

static int _ArmadilloDisassembleNew(struct instruction *i,
        struct ad_insn **_out){
    struct ad_insn *out = *_out;

    unsigned op0 = bits(i->opcode, 25, 28);

    if(op0 <= 3){
        concat(&out->decoded, ".long %#x", i->opcode);
        return AD_OK;
    }
    
    if((op0 & ~0x1) == 0x8){
        out->group = AD_G_DataProcessingImmediate;
        return DataProcessingImmediateDisassemble(i, out);
    }

    return AD_OK;
}

int ArmadilloDisassembleNew(unsigned int opcode, unsigned long PC,
        struct ad_insn **out){
    // XXX *out must be NULL
    if(!out || (out && *out))
        return AD_ERR;

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
