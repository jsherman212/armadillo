#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "adefs.h"
#include "bits.h"
#include "instruction.h"
#include "strext.h"

#include "BranchExcSys.h"
#include "DataProcessingImmediate.h"
#include "DataProcessingFloatingPoint.h"
#include "DataProcessingRegister.h"
#include "LoadsAndStores.h"
unsigned long getbitsinrange(unsigned int number, int start, int amount){
    unsigned int mask = ((1 << amount) - 1) << start;
    return (number & mask) >> start;
}

static int _ArmadilloDisassembleNew(struct instruction *i,
        struct ad_insn **_out){
    struct ad_insn *out = *_out;

    unsigned op0 = bits(i->opcode, 25, 28);

    if(op0 <= 3){
        concat(&DECODE_STR(out), ".long #%#x", i->opcode);
        return 0;
    }
    else if((op0 >> 1) == 4){
        out->group = AD_G_DataProcessingImmediate;
        return DataProcessingImmediateDisassemble(i, out);
    }
    else if((op0 >> 1) == 5){
        out->group = AD_G_BranchExcSys;
        return BranchExcSysDisassemble(i, out);
    }
    else{
        concat(&DECODE_STR(out), ".long #%#x", i->opcode);
        return 0;
    }

    return 0;
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
