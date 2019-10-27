#include <stdio.h>
#include <stdlib.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "utils.h"
#include "strext.h"

static int DisassemblePCRelativeAddressingInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned op = bits(i->opcode, 31, 31);
    unsigned immlo = bits(i->opcode, 29, 30);
    unsigned immhi = bits(i->opcode, 5, 23);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(Rd > AD_RTBL_GEN_64_SZ)
        return 1;

    ADD_FIELD(out, op);
    ADD_FIELD(out, immlo);
    ADD_FIELD(out, immhi);
    ADD_FIELD(out, Rd);

    unsigned long imm = 0;

    const char *instr_s = NULL;

    if(op == 0){
        instr_s = "adr";

        imm = (immhi << 2) | immlo;
        imm = sign_extend(imm, 21);
        imm += i->PC;

        SET_INSTR_ID(out, AD_INSTR_ADR);
    }
    else{
        instr_s = "adrp";

        imm = ((immhi << 2) | immlo) << 12;
        imm = sign_extend(imm, 32);
        imm += (i->PC & ~0xfff);

        SET_INSTR_ID(out, AD_INSTR_ADRP);
    }

    ADD_REG_OPERAND(out, Rd, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

    const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);

    concat(&DECODE_STR(out), "%s %s, %#lx", instr_s, Rd_s, imm);

    return 0;
}

static int DisassembleAddSubtractImmediateInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned sf = bits(i->opcode, 31, 31);
    unsigned op = bits(i->opcode, 30, 30);
    unsigned S = bits(i->opcode, 29, 29);
    unsigned sh = bits(i->opcode, 22, 22);
    unsigned imm12 = bits(i->opcode, 10, 21);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    const char **registers = AD_RTBL_GEN_32;
    size_t len = AD_RTBL_GEN_32_SZ;

    if(sf){
        registers = AD_RTBL_GEN_64;
        len = AD_RTBL_GEN_64_SZ;
    }

    if(Rn > len || Rd > len)
        return 1;

    ADD_FIELD(out, sf);
    ADD_FIELD(out, op);
    ADD_FIELD(out, S);
    ADD_FIELD(out, sh);
    ADD_FIELD(out, imm12);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    unsigned long imm = imm12;

    if(sf)
        imm <<= 12;

    const char *Rd_s = GET_GEN_REG(registers, Rd, NO_PREFER_ZR);
    const char *Rn_s = GET_GEN_REG(registers, Rn, NO_PREFER_ZR);

    int instr_id = NONE;
    int sz = (registers == AD_RTBL_GEN_64 ? _64_BIT : _32_BIT);
    int shift = sh ? 12 : 0;

    if(S == 0 && op == 0){
        if(sh == 0 && imm12 == 0 && (Rd == 0x1f || Rn == 0x1f)){
            instr_id = AD_INSTR_MOV;

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

            concat(&DECODE_STR(out), "mov %s, %s", Rd_s, Rn_s);
        }
        else{
            instr_id = AD_INSTR_ADD;

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

            concat(&DECODE_STR(out), "add %s, %s, #%#lx", Rd_s, Rn_s, imm);

            if(sh){
                ADD_SHIFT_OPERAND(out, AD_SHIFT_LSL, shift);

                concat(&DECODE_STR(out), ", lsl %d", shift);
            }
        }
    }
    else if(S == 1 && op == 0){
        if(Rd == 0x1f){
            instr_id = AD_INSTR_CMN;

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

            concat(&DECODE_STR(out), "cmn, %s, #%#lx", Rn_s, imm);

            if(sh){
                ADD_SHIFT_OPERAND(out, AD_SHIFT_LSL, shift);

                concat(&DECODE_STR(out), ", lsl %d", shift);
            }
        }
        else{
            instr_id = AD_INSTR_ADDS;

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

            concat(&DECODE_STR(out), "adds %s, %s, %#lx", Rd_s, Rn_s, imm);

            if(sh){
                ADD_SHIFT_OPERAND(out, AD_SHIFT_LSL, shift);

                concat(&DECODE_STR(out), ", lsl %d", shift);
            }
        }
    }
    else if(S == 0 && op == 1){
        instr_id = AD_INSTR_SUB;

        ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

        concat(&DECODE_STR(out), "sub %s, %s, %#lx", Rd_s, Rn_s, imm);

        if(sh){
            ADD_SHIFT_OPERAND(out, AD_SHIFT_LSL, shift);

            concat(&DECODE_STR(out), ", lsl %d", shift);
        }
    }
    else if(S == 1 && op == 1){
        if(Rd == 0x1f){
            instr_id = AD_INSTR_CMP;

            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

            concat(&DECODE_STR(out), "cmp %s, #%#lx", Rn_s, imm);

            if(sh){
                ADD_SHIFT_OPERAND(out, AD_SHIFT_LSL, shift);

                concat(&DECODE_STR(out), ", lsl %d", shift);
            }
        }
        else{
            instr_id = AD_INSTR_SUBS;

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&imm);

            concat(&DECODE_STR(out), "subs %s, %s, #%#lx", Rd_s, Rn_s, imm);

            if(sh){
                ADD_SHIFT_OPERAND(out, AD_SHIFT_LSL, shift);

                concat(&DECODE_STR(out), ", lsl %d", shift);
            }
        }
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleAddSubtractImmediateWithTagsInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned sf = bits(i->opcode, 31, 31);
    unsigned op = bits(i->opcode, 30, 30);
    unsigned S = bits(i->opcode, 29, 29);
    unsigned o2 = bits(i->opcode, 22, 22);
    unsigned uimm6 = bits(i->opcode, 16, 21);
    unsigned op3 = bits(i->opcode, 14, 15);
    unsigned uimm4 = bits(i->opcode, 10, 13);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(sf == 0)
        return 1;

    if(sf == 1 && S == 1)
        return 1;

    if(Rn > AD_RTBL_GEN_64_SZ || Rd > AD_RTBL_GEN_64_SZ)
        return 1;

    const char *instr_s = NULL;
    int instr_id = NONE;

    if(op == 0){
        instr_s = "addg";
        instr_id = AD_INSTR_ADDG;
    }
    else{
        instr_s = "subg";
        instr_id = AD_INSTR_SUBG;
    }

    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);

    ADD_REG_OPERAND(out, Rd, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&uimm6);
    ADD_IMM_OPERAND(out, AD_ULONG, *(unsigned long *)&uimm4);

    SET_INSTR_ID(out, instr_id);

    concat(&DECODE_STR(out), "%s %s, %s, #%#lx, #%#lx", instr_s, Rd_s,
            Rn_s, uimm6, uimm4);

    return 0;
}

//char *DisassembleLogicalImmediateInstr(struct instruction *instruction){
static int DisassembleLogicalImmediateInstr(struct instruction *i,
        struct ad_insn *out){
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

int DataProcessingImmediateDisassemble(struct instruction *i,
        struct ad_insn *out){
    unsigned op0 = bits(i->opcode, 23, 25);

    int result = 0;

    if((op0 >> 1) == 0)
        result = DisassemblePCRelativeAddressingInstr(i, out);
    else if(op0 == 2){
        disassembled = DisassembleAddSubtractImmediateInstr(instruction);
    }
    else if(op0 == 3)
        result = DisassembleAddSubtractImmediateWithTagsInstr(i, out);
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
    else{
        return strdup(".undefined");
    }

    return result;
}
