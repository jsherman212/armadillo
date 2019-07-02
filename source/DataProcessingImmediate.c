#include "DataProcessingImmediate.h"

char *DisassemblePCRelativeAddressingInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int op = getbitsinrange(instruction->opcode, 31, 1);
    unsigned int rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int immhi = getbitsinrange(instruction->opcode, 5, 19);
    unsigned int immlo = getbitsinrange(instruction->opcode, 29, 2);
    unsigned long imm = 0;

    if(op == 0){
        imm = (immhi << 2) | immlo;

        imm = sign_extend(imm, 21);
        imm += instruction->PC;
    }

    const char *instr = "adr";

    if(op == 1){
        // immhi: 18 bits
        // immlo: 2 bits
        // bottom 12 bits masked out adds 12 bits
        // 18 + 2 + 12 = 32, so no need to sign extend
        imm = ((immhi << 2) | immlo) << 12;

        // zero out bottom 12 bits of PC, then add it to the immediate
        imm += (instruction->PC & ~0xfff);

        instr = "adrp";
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, #%#lx", instr, ARM64_GeneralRegisters[rd], imm);

    return disassembled;
}

char *DisassembleAddSubtractImmediateInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int s = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 30, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    unsigned int rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned long imm = getbitsinrange(instruction->opcode, 10, 12);
    unsigned int shift = getbitsinrange(instruction->opcode, 22, 2);

    if(sf == 0)
        imm = (unsigned int)imm;

    // these instructions can modify (w)sp
    const char *rd_reg = registers[rd];

    if(rd == 31)
        rd_reg = sf == 0 ? "wsp" : "sp";

    const char *rn_reg = registers[rn];

    if(rn == 31)
        rn_reg = sf == 0 ? "wsp" : "sp";

    if(shift == (1 << 1))
        return strdup(".undefined");

    if(s == 0 && op == 0){
        disassembled = malloc(128);

        if(shift == 0 && imm == 0 && (rd == 0x1f || rn == 0x1f))
            sprintf(disassembled, "mov %s, %s", rd_reg, rn_reg);
        else
            sprintf(disassembled, "add %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
    }
    else if(s == 1 && op == 0){
        disassembled = malloc(128);

        if(rd == 0x1f)
            sprintf(disassembled, "cmn %s, #%#lx%s", rn_reg, imm, shift == 1 ? ", lsl 12" : "");
        else
            sprintf(disassembled, "adds %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
    }
    else if(s == 0 && op == 1){
        disassembled = malloc(128);
        sprintf(disassembled, "sub %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
    }
    else if(op == 1 && s == 1){
        disassembled = malloc(128);

        if(rd == 0x1f)
            sprintf(disassembled, "cmp %s, #%#lx%s", rn_reg, imm, shift == 1 ? ", lsl 12" : "");
        else
            sprintf(disassembled, "subs %s, %s, #%#lx%s", rd_reg, rn_reg, imm, shift == 1 ? ", lsl 12" : "");
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleLogicalImmediateInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int n = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int opc = getbitsinrange(instruction->opcode, 29, 2);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_GeneralRegisters;

    if(sf == 0)
        registers = ARM64_32BitGeneralRegisters;

    if(sf == 0 && n == 1)
        return strdup(".undefined");

    unsigned int rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imms = getbitsinrange(instruction->opcode, 10, 6); 
    unsigned int immr = getbitsinrange(instruction->opcode, 16, 6);
    unsigned long imm;

    DecodeBitMasks(n, imms, immr, 1, &imm);

    if(imm == -1)
        return strdup(".undefined");

    // these instructions can modify (w)sp
    const char *rd_reg = registers[rd];

    if(rd == 31)
        rd_reg = sf == 0 ? "wsp" : "sp";

    const char *rn_reg = registers[rn];

    if(rn == 31)
        rn_reg = sf == 0 ? "wsp" : "sp";

    if(opc == 0){
        disassembled = malloc(128);
        sprintf(disassembled, "and %s, %s, #%#lx", rd_reg, rn_reg, imm);
    }
    else if(opc == 1){
        disassembled = malloc(128);

        if(rn == 0x1f && !MoveWidePreferred(sf, n, imms, immr))
            sprintf(disassembled, "mov %s, #%#lx", rd_reg, imm);
        else
            sprintf(disassembled, "orr %s, %s, #%#lx", rd_reg, registers[rn], imm);
    }
    else if(opc == (1 << 1)){
        disassembled = malloc(128);
        sprintf(disassembled, "eor %s, %s, #%#lx", rd_reg, registers[rn], imm);
    }
    else if(opc == 0x3){
        disassembled = malloc(128);

        if(rd == 0x1f)
            sprintf(disassembled, "tst %s, #%#lx", registers[rn], imm);
        else
            sprintf(disassembled, "ands %s, %s, #%#lx", registers[rd], registers[rn], imm);
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleMoveWideImmediateInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int hw = getbitsinrange(instruction->opcode, 21, 2);
    unsigned int opc = getbitsinrange(instruction->opcode, 29, 2);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    if(opc == 1)
        return strdup(".undefined");

    if(sf == 0 && (hw >> 1) == 1)
        return strdup(".undefined");

    const char **registers = ARM64_GeneralRegisters;

    if(sf == 0)
        registers = ARM64_32BitGeneralRegisters;

    unsigned int rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned long imm16 = getbitsinrange(instruction->opcode, 5, 16);
    unsigned int shift = hw << 4;

    if(opc == 0){
        disassembled = malloc(128);

        int usealias = 0;

        if(sf == 0)
            usealias = !(IsZero(imm16) && hw != 0) && !IsOnes(imm16, 16);
        else
            usealias = !(IsZero(imm16) && hw != 0);

        long result = ~(imm16 << shift);

        if(usealias)
            sprintf(disassembled, "movn %s, #%#lx", registers[rd], sf == 0 ? ~((result << 32) >> 32) : ~result);
        else{
            sprintf(disassembled, "mov %s, #%#lx", registers[rd], imm16);

            if(shift != 0){
                char *lslstr = malloc(64);
                sprintf(lslstr, ", lsl #%d", shift);
                sprintf(disassembled, "%s%s", disassembled, lslstr);
                free(lslstr);
            }
        }
    }
    else if(opc == 0x2){
        disassembled = malloc(128);

        if(!(IsZero(imm16) && hw != 0))
            sprintf(disassembled, "mov %s, #%#lx", registers[rd], imm16 << shift);
        else{
            sprintf(disassembled, "movz %s, #%#lx", registers[rd], imm16);

            if(shift != 0){
                char *lslstr = malloc(64);
                sprintf(lslstr, ", lsl #%d", shift);
                sprintf(disassembled, "%s%s", disassembled, lslstr);
                free(lslstr);
            }
        }
    }
    else if(opc == 0x3){
        disassembled = malloc(128);

        sprintf(disassembled, "movk %s, #%#lx", registers[rd], imm16);

        if(shift != 0){
            char *lslstr = malloc(64);
            sprintf(lslstr, ", lsl #%d", shift);
            sprintf(disassembled, "%s%s", disassembled, lslstr);
            free(lslstr);
        }
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleBitfieldInstruction(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int n = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int opc = getbitsinrange(instruction->opcode, 29, 2);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    if(opc == 0x3)
        return strdup(".undefined");

    if(sf == 0 && n == 1)
        return strdup(".undefined");

    if(sf == 1 && n == 0)
        return strdup(".undefined");

    const char **registers = ARM64_GeneralRegisters;

    if(sf == 0)
        registers = ARM64_32BitGeneralRegisters;

    unsigned int rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imms = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int immr = getbitsinrange(instruction->opcode, 16, 6);

    if(sf == 1 && n != 1)
        return strdup(".undefined");

    if(sf == 0 && (n != 0 || (immr & (1 << 5)) != 0 || (imms & (1 << 5)) != 0))
        return strdup(".undefined");

    int regsize = sf == 0 ? 32 : 64;

    if(opc == 0){
        disassembled = malloc(128);

        if((sf == 1 && imms == 0x3f) || (sf == 0 && imms == 0x1f))
            sprintf(disassembled, "asr %s, %s, #%#x", registers[rd], registers[rn], immr);
        else if(imms < immr)
            sprintf(disassembled, "sbfiz %s, %s, #%#x, #%#x", registers[rd], registers[rn], regsize - immr, imms + 1);
        else if(BFXPreferred(sf, (opc >> 1), imms, immr))
            sprintf(disassembled, "sbfx %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms - immr + 1);
        else if(immr == 0){
            const char *instr = "sxtb";

            if(imms == 0xf)
                instr = "sxth";
            else if(imms == 0x1f)
                instr = "sxtw";

            sprintf(disassembled, "%s %s, %s", instr, sf == 0 ? ARM64_32BitGeneralRegisters[rd] : ARM64_GeneralRegisters[rd], ARM64_32BitGeneralRegisters[rn]);
        }
        else
            sprintf(disassembled, "sbfm %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms);
    }
    else if(opc == 1){
        disassembled = malloc(128);

        if(imms < immr){
            immr = regsize - immr;
            imms += 1;

            // assume bfc
            const char *instr = "bfc";

            if(rd != 0x1f)
                instr = "bfi";

            sprintf(disassembled, "%s %s, %s, #%#x, #%#x", instr, registers[rd], registers[rn], immr, imms);
        }
        else if(imms >= immr)
            sprintf(disassembled, "bfxil %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms - immr + 1);
        else
            sprintf(disassembled, "bfm %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms);
    }
    else if(opc == 0x2){
        disassembled = malloc(128);

        if(imms + 1 == immr){
            if((sf == 0 && imms != 0x1f) || (sf == 1 && imms != 0x3f))
                sprintf(disassembled, "lsl %s, %s, #%#x", registers[rd], registers[rn], -immr % regsize);
        }
        else if((sf == 0 && imms == 0x1f) || (sf == 1 && imms == 0x3f))
            sprintf(disassembled, "lsr %s, %s, #%#x", registers[rd], registers[rn], immr);
        else if(imms < immr)
            sprintf(disassembled, "ubfiz %s, %s, #%#x, #%#x", registers[rd], registers[rn], regsize - immr, imms + 1);
        else if(BFXPreferred(sf, (opc >> 1), imms, immr))
            sprintf(disassembled, "ubfx %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms - immr + 1);
        else if(immr == 0){
            // imms == 0x7
            const char *instr = "uxtb";

            if(imms == 0xf)
                instr = "uxth";

            sprintf(disassembled, "%s %s, %s", instr, ARM64_32BitGeneralRegisters[rd], ARM64_32BitGeneralRegisters[rn]);
        }
        else
            sprintf(disassembled, "ubfm %s, %s, #%#x, #%#x", registers[rd], registers[rn], immr, imms);
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleExtractInstruction(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int imms = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int o0 = getbitsinrange(instruction->opcode, 21, 1);
    unsigned int n = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int op21 = getbitsinrange(instruction->opcode, 29, 2);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    if(n != sf)
        return strdup(".undefined");

    if(sf == 0 && ((imms >> 5) & 1) == 1)
        return strdup(".undefined");

    const char **registers = ARM64_GeneralRegisters;

    if(sf == 0)
        registers = ARM64_32BitGeneralRegisters;

    unsigned int rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int rm = getbitsinrange(instruction->opcode, 16, 5);

    if(op21 == 0 && (n == 0 || n == 1) && o0 == 0){
        disassembled = malloc(128);

        if(rn == rm)
            sprintf(disassembled, "ror %s, %s, #%#x", registers[rd], registers[rn], imms);
        else
            sprintf(disassembled, "extr %s, %s, %s, #%#x", registers[rd], registers[rn], registers[rm], imms);
    }
    else
        return strdup(".undefined");

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DataProcessingImmediateDisassemble(struct instruction *instruction){
    unsigned int op0 = getbitsinrange(instruction->opcode, 24, 2);
    unsigned int op1 = getbitsinrange(instruction->opcode, 22, 2);

    char *disassembled = NULL;

    if(op0 == 0)
        disassembled = DisassemblePCRelativeAddressingInstr(instruction);
    else if(op0 == 0x1){
        if((op1 >> 0x1) != 0x1)
            disassembled = DisassembleAddSubtractImmediateInstr(instruction);
        else
            return strdup(".undefined");
    }
    else if(op0 == 0x2){
        if((op1 >> 0x1) == 0)
            disassembled = DisassembleLogicalImmediateInstr(instruction);
        else
            disassembled = DisassembleMoveWideImmediateInstr(instruction);
    }
    else if(op0 == 0x3){
        if((op1 >> 0x1) == 0)
            disassembled = DisassembleBitfieldInstruction(instruction);
        else
            disassembled = DisassembleExtractInstruction(instruction);
    }
    else
        return strdup(".undefined");

    return disassembled;
}
