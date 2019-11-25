#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "utils.h"
#include "strext.h"

#define SHIFTED 0
#define EXTENDED 1

#define REGISTER 0
#define IMMEDIATE 1

static int DisassembleDataProcessingTwoSourceInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned sf = bits(i->opcode, 31, 31);
    unsigned S = bits(i->opcode, 29, 29);
    unsigned Rm = bits(i->opcode, 16, 20); 
    unsigned opcode = bits(i->opcode, 10, 15);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    ADD_FIELD(out, sf);
    ADD_FIELD(out, S);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    struct itab itab[] = {
        { "subp", AD_INSTR_SUBP }, { NULL, NONE }, { "udiv", AD_INSTR_UDIV },
        { "sdiv", AD_INSTR_SDIV }, { "irg", AD_INSTR_IRG }, { "gmi", AD_INSTR_GMI },
        { NULL, NONE }, { NULL, NONE }, { "lslv", AD_INSTR_LSLV },
        { "lsrv", AD_INSTR_LSRV }, { "asrv", AD_INSTR_ASRV },
        { "rorv", AD_INSTR_RORV }, { "pacga", AD_INSTR_PACGA },
        { NULL, NONE }, { NULL, NONE }, { NULL, NONE }, { "crc32b", AD_INSTR_CRC32B },
        { "crc32h", AD_INSTR_CRC32H }, { "crc32w", AD_INSTR_CRC32W },
        { "crc32x", AD_INSTR_CRC32X }, { "crc32cb", AD_INSTR_CRC32CB },
        { "crc32ch", AD_INSTR_CRC32CH }, { "crc32cw", AD_INSTR_CRC32CW },
        { "crc32cx", AD_INSTR_CRC32CX }
    };

    if(OOB(opcode, itab))
        return 1;

    const char *instr_s = itab[opcode].instr_s;

    if(!instr_s)
        return 1;

    int instr_id = itab[opcode].instr_id;

    if(S == 1 && sf == 1 && opcode == 0){
        instr_s = "subps";
        instr_id = AD_INSTR_SUBPS;

        /* subps --> cmpp */
        if(Rd == 0x1f){
            instr_s = "cmpp";
            instr_id = AD_INSTR_CMPP;
        }
    }

    SET_INSTR_ID(out, instr_id);

    concat(&DECODE_STR(out), "%s ", instr_s);

    if(strstr(instr_s, "crc")){
        ADD_REG_OPERAND(out, Rd, _SZ(_32_BIT), PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_32));
        ADD_REG_OPERAND(out, Rn, _SZ(_32_BIT), PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_32));

        const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_32, Rd, PREFER_ZR);
        const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_32, Rn, PREFER_ZR);

        concat(&DECODE_STR(out), "%s, %s", Rd_s, Rn_s);

        const char *Rm_s = NULL;

        if(sf == 1){
            ADD_REG_OPERAND(out, Rm, _SZ(_64_BIT), PREFER_ZR, _SYSREG(NONE),
                    _RTBL(AD_RTBL_GEN_64));
            Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, PREFER_ZR);
        }
        else{
            ADD_REG_OPERAND(out, Rm, _SZ(_32_BIT), PREFER_ZR, _SYSREG(NONE),
                    _RTBL(AD_RTBL_GEN_32));
            Rm_s = GET_GEN_REG(AD_RTBL_GEN_32, Rm, PREFER_ZR);
        }

        concat(&DECODE_STR(out), ", %s", Rm_s);
    }
    else if(instr_id == AD_INSTR_UDIV || instr_id == AD_INSTR_SDIV ||
            instr_id == AD_INSTR_LSLV || instr_id == AD_INSTR_LSRV ||
            instr_id == AD_INSTR_ASRV || instr_id == AD_INSTR_RORV){
        const char **registers = AD_RTBL_GEN_32;
        int sz = _32_BIT;

        if(sf == 1){
            registers = AD_RTBL_GEN_64;
            sz = _64_BIT;
        }

        ADD_REG_OPERAND(out, Rd, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rn, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

        const char *Rd_s = GET_GEN_REG(registers, Rd, PREFER_ZR);
        const char *Rn_s = GET_GEN_REG(registers, Rn, PREFER_ZR);
        const char *Rm_s = GET_GEN_REG(registers, Rm, PREFER_ZR);

        concat(&DECODE_STR(out), "%s, %s, %s", Rd_s, Rn_s, Rm_s);
    }
    else{
        if(instr_id != AD_INSTR_CMPP){
            int prefer_zr = instr_id != AD_INSTR_IRG;

            ADD_REG_OPERAND(out, Rd, _SZ(_64_BIT), prefer_zr, _SYSREG(NONE),
                    _RTBL(AD_RTBL_GEN_64));
            const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, prefer_zr);

            concat(&DECODE_STR(out), "%s, ", Rd_s);
        }

        int prefer_zr = instr_id == AD_INSTR_PACGA;

        ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), prefer_zr, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));
        const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, prefer_zr);

        concat(&DECODE_STR(out), "%s", Rn_s);

        if(instr_id == AD_INSTR_IRG && Rm == 0x1f)
            return 0;

        prefer_zr = (instr_id == AD_INSTR_IRG || instr_id == AD_INSTR_GMI);

        ADD_REG_OPERAND(out, Rm, _SZ(_64_BIT), prefer_zr, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));
        const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, prefer_zr);

        concat(&DECODE_STR(out), ", %s", Rm_s);
    }

    return 0;
}

static int DisassembleDataProcessingOneSourceInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned sf = bits(i->opcode, 31, 31);
    unsigned S = bits(i->opcode, 29, 29);
    unsigned opcode2 = bits(i->opcode, 16, 20);
    unsigned opcode = bits(i->opcode, 10, 15);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    ADD_FIELD(out, sf);
    ADD_FIELD(out, S);
    ADD_FIELD(out, opcode2);
    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    int instr_id = NONE;

    if(opcode2 == 0){
        if(sf == 0 && S == 0 && opcode2 == 0 && opcode == 3)
            return 1;

        struct itab tab[] = {
            { "rbit", AD_INSTR_RBIT }, { "rev16", AD_INSTR_REV16 },
            { "rev", AD_INSTR_REV }, { "rev32", AD_INSTR_REV32 },
            { "clz", AD_INSTR_CLZ }, { "cls", AD_INSTR_CLS },
        };

        if(OOB(opcode, tab))
            return 1;

        const char *instr_s = tab[opcode].instr_s;
        instr_id = tab[opcode].instr_id;

        if(sf == 1){
            if(opcode == 2){
                instr_s = "rev32";
                instr_id = AD_INSTR_REV32;
            }
            else if(opcode == 3){
                instr_s = "rev";
                instr_id = AD_INSTR_REV;
            }
        }

        const char **registers = sf == 1 ? AD_RTBL_GEN_64 : AD_RTBL_GEN_32;
        int sz = sf == 1 ? _64_BIT : _32_BIT;

        ADD_REG_OPERAND(out, Rd, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rn, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

        const char *Rd_s = GET_GEN_REG(registers, Rd, PREFER_ZR);
        const char *Rn_s = GET_GEN_REG(registers, Rn, PREFER_ZR);

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rd_s, Rn_s);
    }
    else if(opcode2 == 1 && opcode < 8){
        struct itab tab[] = {
            { "pacia", AD_INSTR_PACIA }, { "pacib", AD_INSTR_PACIB },
            { "pacda", AD_INSTR_PACDA }, { "pacdb", AD_INSTR_PACDB },
            { "autia", AD_INSTR_AUTIA }, { "autib", AD_INSTR_AUTIB },
            { "autda", AD_INSTR_AUTDA }, { "autdb", AD_INSTR_AUTDB }
        };

        if(OOB(opcode, tab))
            return 1;

        const char *instr_s = tab[opcode].instr_s;
        instr_id = tab[opcode].instr_id;

        ADD_REG_OPERAND(out, Rd, _SZ(_64_BIT), PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));
        ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));

        const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, PREFER_ZR);
        const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rd_s, Rn_s);
    }
    else if(opcode2 == 1 && opcode >= 8 && Rn == 0x1f){
        struct itab tab[] = {
            { "paciza", AD_INSTR_PACIZA }, { "pacizb", AD_INSTR_PACIZB },
            { "pacdza", AD_INSTR_PACDZA }, { "pacdzb", AD_INSTR_PACDZB },
            { "autiza", AD_INSTR_AUTIZA }, { "autizb", AD_INSTR_AUTIZB },
            { "autdza", AD_INSTR_AUTDZA }, { "autdzb", AD_INSTR_AUTDZB },
            { "xpaci", AD_INSTR_XPACI }, { "xpacd", AD_INSTR_XPACD }
        };

        opcode -= 8;

        if(OOB(opcode, tab))
            return 1;

        const char *instr_s = tab[opcode].instr_s;
        instr_id = tab[opcode].instr_id;

        ADD_REG_OPERAND(out, Rd, _SZ(_64_BIT), PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));

        const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, PREFER_ZR);

        concat(&DECODE_STR(out), "%s %s", instr_s, Rd_s);
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static const char *decode_shift(unsigned op){
    switch(op){
        case 0: return "lsl";
        case 1: return "lsr";
        case 2: return "asr";
        case 3: return "ror";
        default: return NULL;
    };
}

static int DisassembleLogicalShiftedRegisterInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned sf = bits(i->opcode, 31, 31);
    unsigned opc = bits(i->opcode, 29, 30);
    unsigned shift = bits(i->opcode, 22, 23);
    unsigned N = bits(i->opcode, 21, 21);
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned imm6 = bits(i->opcode, 10, 15);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(sf == 0 && (imm6 >> 5) == 1)
        return 1;

    ADD_FIELD(out, sf);
    ADD_FIELD(out, opc);
    ADD_FIELD(out, shift);
    ADD_FIELD(out, N);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, imm6);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    const char **registers = sf == 0 ? AD_RTBL_GEN_32 : AD_RTBL_GEN_64;
    int sz = sf == 0 ? _32_BIT : _64_BIT;

    struct itab tab[] = {
        { "and", AD_INSTR_AND }, { "bic", AD_INSTR_BIC }, { "orr", AD_INSTR_ORR },
        { "orn", AD_INSTR_ORN }, { "eor", AD_INSTR_EOR }, { "eon", AD_INSTR_EON },
        { "ands", AD_INSTR_ANDS }, { "bics", AD_INSTR_BICS }
    };

    unsigned idx = (opc << 1) | N;

    if(OOB(idx, tab))
        return 1;

    const char *instr_s = tab[idx].instr_s;
    int instr_id = tab[idx].instr_id;

    const char *Rd_s = GET_GEN_REG(registers, Rd, PREFER_ZR);
    const char *Rn_s = GET_GEN_REG(registers, Rn, PREFER_ZR);
    const char *Rm_s = GET_GEN_REG(registers, Rm, PREFER_ZR);

    if(instr_id == AD_INSTR_ORR && shift == 0 && imm6 == 0 && Rn == 0x1f){
        instr_s = "mov";
        instr_id = AD_INSTR_MOV;

        ADD_REG_OPERAND(out, Rd, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rd_s, Rm_s);
    }
    else if(instr_id == AD_INSTR_ORN && Rn == 0x1f){
        instr_s = "mvn";
        instr_id = AD_INSTR_MVN;

        ADD_REG_OPERAND(out, Rd, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rd_s, Rm_s);
    }
    else if(instr_id == AD_INSTR_ANDS && Rd == 0x1f){
        instr_s = "tst";
        instr_id = AD_INSTR_TST;

        ADD_REG_OPERAND(out, Rn, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rn_s, Rm_s);
    }
    else{
        ADD_REG_OPERAND(out, Rd, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rn, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

        concat(&DECODE_STR(out), "%s %s, %s, %s", instr_s, Rd_s, Rn_s, Rm_s);
    }

    SET_INSTR_ID(out, instr_id);

    unsigned amount = imm6;

    /* no need to include <shift>, #<amount> */
    if(instr_id == AD_INSTR_MOV || amount == 0)
        return 0;

    const char *shift_type = decode_shift(shift);

    if(!shift_type)
        return 1;

    ADD_SHIFT_OPERAND(out, shift, amount);

    concat(&DECODE_STR(out), ", %s #"S_X"", shift_type, S_A(amount));

    return 0;
}

static int get_extended_Rm(unsigned option, char **regstr, unsigned Rm,
        unsigned *sz, const char ***registers){
    int _64_bit = (option & ~4) == 3;

    if(_64_bit)
        concat(regstr, "x");
    else
        concat(regstr, "w");

    if(Rm == 0x1f)
        concat(regstr, "zr");
    else
        concat(regstr, "%d", Rm);

    *sz = _64_bit ? _64_BIT : _32_BIT;
    *registers = _64_bit ? AD_RTBL_GEN_64 : AD_RTBL_GEN_32;

    return _64_bit;
}

static char *get_extended_extend_string(unsigned option, unsigned sf,
        unsigned Rd, unsigned Rn, unsigned imm3){
    char *extend_string = NULL;
    const char *extend = decode_reg_extend(option);

    int is_lsl = 0;

    if(Rd == 0x1f || Rn == 0x1f){
        if((sf == 0 && option == 2) || (sf == 1 && option == 3)){
            if(imm3 == 0)
                extend = "";
            else{
                extend = "lsl";
                is_lsl = 1;
            }
        }
    }

    unsigned amount = imm3;

    if(*extend)
        concat(&extend_string, "%s", extend);

    if(is_lsl || (!is_lsl && amount != 0))
        concat(&extend_string, " #"S_X"", S_A(amount));

    return extend_string;
}

static int DisassembleAddSubtractShiftedOrExtendedInstr(struct instruction *i,
        struct ad_insn *out, int kind){
    unsigned sf = bits(i->opcode, 31, 31);
    unsigned op = bits(i->opcode, 30, 30);
    unsigned S = bits(i->opcode, 29, 29);
    unsigned shift = bits(i->opcode, 22, 23);
    unsigned opt = shift;
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned option = bits(i->opcode, 13, 15);
    unsigned imm3 = bits(i->opcode, 10, 12);
    unsigned imm6 = (option << 3) | imm3;
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    ADD_FIELD(out, sf);
    ADD_FIELD(out, op);
    ADD_FIELD(out, S);

    if(kind == SHIFTED)
        ADD_FIELD(out, shift);
    else
        ADD_FIELD(out, opt);

    ADD_FIELD(out, Rm);

    if(kind == SHIFTED)
        ADD_FIELD(out, imm6);
    else{
        ADD_FIELD(out, option);
        ADD_FIELD(out, imm3);
    }

    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    struct itab tab[] = {
        { "add", AD_INSTR_ADD }, { "adds", AD_INSTR_ADDS },
        { "sub", AD_INSTR_SUB }, { "subs", AD_INSTR_SUBS }
    };

    unsigned idx = (op << 1) | S;

    if(OOB(idx, tab))
        return 1;

    const char *instr_s = tab[idx].instr_s;
    int instr_id = tab[idx].instr_id;

    int prefer_zr_Rd_Rn = kind == SHIFTED;

    const char **registers = sf == 1 ? AD_RTBL_GEN_64 : AD_RTBL_GEN_32;
    int sz = sf == 1 ? _64_BIT : _32_BIT;

    /* Both shifted and extended have aliases for ADDS and SUBS,
     * but only shifted has aliases for SUB.
     */
    if((instr_id == AD_INSTR_ADDS || instr_id == AD_INSTR_SUBS) && Rd == 0x1f){
        if(instr_id == AD_INSTR_ADDS){
            instr_s = "cmn";
            instr_id = AD_INSTR_CMN;
        }
        else if(instr_id == AD_INSTR_SUBS){
            instr_s = "cmp";
            instr_id = AD_INSTR_CMP;
        }

        ADD_REG_OPERAND(out, Rn, sz, prefer_zr_Rd_Rn, _SYSREG(NONE),
                _RTBL(registers));
        const char *Rn_s = GET_GEN_REG(registers, Rn, prefer_zr_Rd_Rn);

        char *Rm_s = NULL;

        if(kind == SHIFTED || (kind == EXTENDED && sf == 0)){
            ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE),
                    _RTBL(registers));
            Rm_s = (char *)GET_GEN_REG(registers, Rm, PREFER_ZR);
        }
        else{
            unsigned sz = 0;
            const char **registers = NULL;
            int _64_bit = get_extended_Rm(option, &Rm_s, Rm, &sz, &registers);

            ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        }

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rn_s, Rm_s);

        if(kind == EXTENDED && sf == 1)
            free(Rm_s);
    }
    else if((instr_id == AD_INSTR_SUB || instr_id == AD_INSTR_SUBS) &&
            Rn == 0x1f && kind == SHIFTED){
        if(instr_id == AD_INSTR_SUB){
            instr_s = "neg";
            instr_id = AD_INSTR_NEG;
        }
        else if(instr_id == AD_INSTR_SUBS){
            instr_s = "negs";
            instr_id = AD_INSTR_NEGS;
        }

        ADD_REG_OPERAND(out, Rd, sz, prefer_zr_Rd_Rn, _SYSREG(NONE),
                _RTBL(registers));
        ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE),
                _RTBL(registers));

        const char *Rd_s = GET_GEN_REG(registers, Rd, prefer_zr_Rd_Rn);
        const char *Rm_s = GET_GEN_REG(registers, Rm, PREFER_ZR);

        concat(&DECODE_STR(out), "%s %s, %s", instr_s, Rd_s, Rm_s);
    }
    else{
        ADD_REG_OPERAND(out, Rd, sz, prefer_zr_Rd_Rn, _SYSREG(NONE), _RTBL(registers));
        ADD_REG_OPERAND(out, Rn, sz, prefer_zr_Rd_Rn, _SYSREG(NONE), _RTBL(registers));

        const char *Rd_s = GET_GEN_REG(registers, Rd, prefer_zr_Rd_Rn);
        const char *Rn_s = GET_GEN_REG(registers, Rn, prefer_zr_Rd_Rn);

        char *Rm_s = NULL;

        if(kind == SHIFTED || (kind == EXTENDED && sf == 0)){
            ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE),
                    _RTBL(registers));
            Rm_s = (char *)GET_GEN_REG(registers, Rm, PREFER_ZR);
        }
        else{
            unsigned sz = 0;
            const char **registers = NULL;
            int _64_bit = get_extended_Rm(option, &Rm_s, Rm, &sz, &registers);

            ADD_REG_OPERAND(out, Rm, sz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
        }

        concat(&DECODE_STR(out), "%s %s, %s, %s", instr_s, Rd_s, Rn_s, Rm_s);

        if(kind == EXTENDED && sf == 1)
            free(Rm_s);
    }

    if(kind == SHIFTED){
        if(shift == 3)
            return 1;

        const char *shift_type = decode_shift(shift);

        unsigned amount = imm6;

        if(amount != 0){
            ADD_SHIFT_OPERAND(out, shift, amount);

            concat(&DECODE_STR(out), ", %s #"S_X"", shift_type, S_A(amount));
        }
    }
    else{
        char *extend_string = get_extended_extend_string(option, sf, Rd, Rn, imm3);

        if(extend_string)
            concat(&DECODE_STR(out), ", %s", extend_string);

        free(extend_string);
    }


    SET_INSTR_ID(out, instr_id);

    return 0;
}
/*
char *DisassembleAddSubtractShiftedOrExtendedInstr(struct instruction *instruction, int kind){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm3 = getbitsinrange(instruction->opcode, 10, 3);
    unsigned int option = getbitsinrange(instruction->opcode, 13, 3);
    unsigned int imm6 = (option << 3) | imm3;
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int shift = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int opt = shift;
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 30, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    if(kind == SHIFTED && shift == 3)
        return strdup(".undefined");

    unsigned int encoding = (sf << 2) | (op << 1) | S;

    const char *instr_tbl[] = {"add", "adds", "sub", "subs"};


    const char *instr = NULL;

    if(sf == 0){
        if(!check_bounds(encoding, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding];
    }
    else{
        if(!check_bounds(encoding - 4, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding - 4];
    }

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    const char *_Rd = registers[Rd];
    const char *_Rn = registers[Rn];
    const char *_Rm = registers[Rm];

    const char *_shift = decode_shift(shift);

    if(kind == EXTENDED){
        if(strcmp(instr, "add") == 0 || strcmp(instr, "sub") == 0){
            if(sf == 0){
                _Rd = Rd == 31 ? "wsp" : registers[Rd];
                _Rn = Rn == 31 ? "wsp" : registers[Rn];
            }
            else{
                _Rd = Rd == 31 ? "sp" : registers[Rd];
                _Rn = Rn == 31 ? "sp" : registers[Rn];
            }
        }
        else if(strcmp(instr, "adds") == 0 || strcmp(instr, "subs") == 0){
            if(sf == 0)
                _Rn = Rn == 31 ? "wsp" : registers[Rn];
            else
                _Rn = Rn == 31 ? "sp" : registers[Rn];
        }
    }

    disassembled = malloc(128);

    if(kind == SHIFTED){
        if(strcmp(instr, "adds") == 0 && Rd == 0x1f)
            sprintf(disassembled, "cmn %s, %s", _Rn, _Rm);
        else if(strcmp(instr, "sub") == 0 && Rn == 0x1f)
            sprintf(disassembled, "neg %s, %s", _Rd, _Rm);
        else if(strcmp(instr, "subs") == 0 && (Rd == 0x1f || Rn == 0x1f)){
            if(Rd == 0x1f)
                sprintf(disassembled, "cmp %s, %s", _Rn, _Rm);

            else if(Rn == 0x1f)
                sprintf(disassembled, "negs %s, %s", _Rd, _Rm);
        }
        else
            sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

        if(imm6 != 0)
            sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
    }

    if(kind == EXTENDED){
        char R = 'w';

        if(option == 3 || option == 7)
            R = 'x';

        char *extend = decode_reg_extend(option);

        if(strcmp(instr, "add") == 0 || strcmp(instr, "sub") == 0){
            if(Rd == 0x1f || Rn == 0x1f){
                if(sf == 0 && option == 2)
                    extend = "lsl";

                if(sf == 1 && option == 3)
                    extend = "lsl";
            }

            sprintf(disassembled, "%s %s, %s, %c%d", instr, _Rd, _Rn, R, Rm);

            if(imm3 != 0)
                sprintf(disassembled, "%s, %s #%d", disassembled, extend, imm3);
        }
        else{
            if(Rn == 0x1f){
                if(sf == 0 && option == 2)
                    extend = "lsl";

                if(sf == 1 && option == 3)
                    extend = "lsl";
            }

            // check for aliases	
            if(strcmp(instr, "adds") == 0 && Rd == 0x1f){
                sprintf(disassembled, "cmn %s, %s, %s", _Rn, _Rm, extend);

                if(imm3 != 0)
                    sprintf(disassembled, "%s #%d", disassembled, imm3);
            }
            else if(strcmp(instr, "subs") && Rd == 0x1f){
                sprintf(disassembled, "cmp %s, %s, %s", _Rn, _Rm, extend);

                if(imm3 != 0)
                    sprintf(disassembled, "%s #%d", disassembled, imm3);
            }
            else{
                sprintf(disassembled, "%s %s, %s, %c%d", instr, _Rd, _Rn, R, Rm);

                if(imm3 != 0)
                    sprintf(disassembled, "%s, %s #%d", disassembled, extend, imm3);

                if(imm3 == 0 && Rn == 0x1f){
                    if(R == 'w')
                        strcat(disassembled, ", uxtw");
                }
            }
        }
    }

    return disassembled;
}

char *DisassembleAddSubtractCarryInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 30, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    unsigned int encoding = (sf << 2) | (op << 1) | S;

    const char *instr_tbl[] = {"adc", "adcs", "sdc", "sdcs"};	
    const char *instr = NULL;

    if(sf == 0){
        if(!check_bounds(encoding, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding];
    }
    else{
        if(!check_bounds(encoding - 4, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding - 4];
    }

    const char *_Rd = registers[Rd];
    const char *_Rn = registers[Rn];
    const char *_Rm = registers[Rm];

    disassembled = malloc(128);

    if(strcmp(instr, "sdc") == 0 && Rn == 0x1f)
        sprintf(disassembled, "ngc %s, %s", _Rd, _Rm);
    else if(strcmp(instr, "sdcs") == 0 && Rn == 0x1f)
        sprintf(disassembled, "ngcs %s, %s", _Rd, _Rm);
    else
        sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleRotateRightIntoFlagsInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int mask = getbitsinrange(instruction->opcode, 0, 4);
    unsigned int o2 = getbitsinrange(instruction->opcode, 4, 1);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm6 = getbitsinrange(instruction->opcode, 15, 6);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 30, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    disassembled = malloc(128);

    if(sf == 1 && op == 0 && S == 1 && o2 == 0){
        sprintf(disassembled, "rmif %s, #%#x, #%d", ARM64_GeneralRegisters[Rn], imm6, mask);
        return disassembled;
    }
    else
        return strdup(".undefined");
}

char *DisassembleEvaluateIntoFlagsInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int sz = getbitsinrange(instruction->opcode, 14, 1);

    disassembled = malloc(128);

    if(sz == 0)
        sprintf(disassembled, "setf8 %s", ARM64_32BitGeneralRegisters[Rn]);
    else
        sprintf(disassembled, "setf16 %s", ARM64_32BitGeneralRegisters[Rn]);

    return disassembled;
}

char *DisassembleConditionalCompareInstr(struct instruction *instruction, int kind){
    char *disassembled = NULL;

    unsigned int nzcv = getbitsinrange(instruction->opcode, 0, 4);
    unsigned int o3 = getbitsinrange(instruction->opcode, 4, 1);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int o2 = getbitsinrange(instruction->opcode, 10, 1);
    unsigned int cond = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int imm5 = Rm;
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 30, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    unsigned int encoding = (sf << 2) | (op << 1) | S;

    const char *instr_tbl[] = {NULL, "ccmn", NULL, "ccmp"};


    const char *instr = NULL;

    if(sf == 0){
        if(!check_bounds(encoding, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding];
    }
    else{
        if(!check_bounds(encoding - 4, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding - 4];
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s", instr, registers[Rn]);

    if(kind == REGISTER)
        sprintf(disassembled, "%s, %s", disassembled, registers[Rm]);
    else
        sprintf(disassembled, "%s, #%d", disassembled, imm5);

    char *_cond = decode_cond(cond);

    sprintf(disassembled, "%s, #%d, %s", disassembled, nzcv, _cond);

    free(_cond);

    return disassembled;
}

char *DisassembleConditionalSelectInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int op2 = getbitsinrange(instruction->opcode, 10, 2);
    unsigned int cond = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 30, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    unsigned int encoding = (op << 3) | (S << 2) | op2;

    const char *instr_tbl[] = {"csel", "csinc", NULL, NULL, NULL, NULL, NULL, NULL, "csinv", "csneg"};

    if(!check_bounds(encoding, ARRAY_SIZE(instr_tbl)))
        return strdup(".undefined");

    const char *instr = instr_tbl[encoding];

    if(!instr)
        return strdup(".undefined");

    const char *_Rd = registers[Rd];
    const char *_Rn = registers[Rn];
    const char *_Rm = registers[Rm];

    disassembled = malloc(128);

    if((strcmp(instr, "csinc") == 0 || strcmp(instr, "csinv") == 0) && Rm != 0x1f && (cond >> 1) != 7 && Rn != 0x1f && Rn == Rm){
        char *_cond = decode_cond(cond & ~0x1);

        if(strcmp(instr, "csinc") == 0)
            sprintf(disassembled, "cinc %s, %s, %s", _Rd, _Rn, _cond);
        else if(strcmp(instr, "csinv") == 0)
            sprintf(disassembled, "cinv %s, %s, %s", _Rd, _Rn, _cond);

        free(_cond);
    }
    else if((strcmp(instr, "csinc") == 0 || strcmp(instr, "csinv")) && Rm == 0x1f && (cond >> 1) != 7 && Rn == 0x1f){
        char *_cond = decode_cond(cond & ~0x1);

        if(strcmp(instr, "csinc") == 0)
            sprintf(disassembled, "cset %s, %s", _Rd, _cond);
        else if(strcmp(instr, "csinv") == 0)
            sprintf(disassembled, "csetm %s, %s", _Rd, _cond);

        free(_cond);
    }
    else if(strcmp(instr, "csneg") == 0 && (cond >> 1) != 7 && Rn == Rm){
        char *_cond = decode_cond(cond & ~0x1);

        sprintf(disassembled, "cneg %s, %s, %s", _Rd, _Rn, _cond);

        free(_cond);
    }
    else{
        char *_cond = decode_cond(cond);
        sprintf(disassembled, "%s %s, %s, %s, %s", instr, _Rd, _Rn, _Rm, _cond);
        free(_cond);
    }

    return disassembled;
}

char *DisassembleDataProcessingThreeSourceInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int Ra = getbitsinrange(instruction->opcode, 10, 5);
    unsigned int o0 = getbitsinrange(instruction->opcode, 15, 1);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int op31 = getbitsinrange(instruction->opcode, 21, 3);
    unsigned int op54 = getbitsinrange(instruction->opcode, 29, 2);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    unsigned int encoding = (op31 << 1) | o0;

    const char *instr_tbl[] = {"madd", "msub", "smaddl", "smsubl", "smulh", NULL,
        NULL, NULL, NULL, NULL, "umaddl", "umsubl", "umulh"};
    const char *instr = instr_tbl[encoding];

    if(!instr)
        return strdup(".undefined");

    const char *_Rd = registers[Rd];
    const char *_Rn = registers[Rn];
    const char *_Ra = registers[Ra];
    const char *_Rm = registers[Rm];

    disassembled = malloc(128);

    if(Ra == 0x1f && strcmp(instr, "smulh") != 0 && strcmp(instr, "umulh") != 0){
        if(strcmp(instr, "madd") == 0)
            sprintf(disassembled, "mul %s, %s, %s", _Rd, _Rn, _Rm);
        else if(strcmp(instr, "msub") == 0)
            sprintf(disassembled, "mneg %s, %s, %s", _Rd, _Rn, _Rm);
        else if(strcmp(instr, "smaddl") == 0)
            sprintf(disassembled, "smull %s, %s, %s", ARM64_GeneralRegisters[Rd], ARM64_32BitGeneralRegisters[Rn], ARM64_32BitGeneralRegisters[Rm]);
        else if(strcmp(instr, "smsubl") == 0)
            sprintf(disassembled, "smnegl %s, %s, %s", ARM64_GeneralRegisters[Rd], ARM64_32BitGeneralRegisters[Rn], ARM64_32BitGeneralRegisters[Rm]);
        else if(strcmp(instr, "umaddl") == 0)
            sprintf(disassembled, "umull %s, %s, %s", ARM64_GeneralRegisters[Rd], ARM64_32BitGeneralRegisters[Rn], ARM64_32BitGeneralRegisters[Rm]);
        else if(strcmp(instr, "umsubl") == 0)
            sprintf(disassembled, "umnegl %s, %s, %s", ARM64_GeneralRegisters[Rd], ARM64_32BitGeneralRegisters[Rn], ARM64_32BitGeneralRegisters[Rm]);
    }
    else if(op31 == 0)
        sprintf(disassembled, "%s %s, %s, %s, %s", instr, _Rd, _Rn, _Rm, _Ra);
    else if(op31 == 2 || op31 == 6)
        sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);
    else
        sprintf(disassembled, "%s %s, %s, %s, %s", instr, ARM64_GeneralRegisters[Rd], ARM64_32BitGeneralRegisters[Rn], ARM64_32BitGeneralRegisters[Rm], ARM64_GeneralRegisters[Ra]);

    return disassembled;
}
*/

int DataProcessingRegisterDisassemble(struct instruction *i,
        struct ad_insn *out){
    int result = 0;
    
    unsigned op0 = bits(i->opcode, 30, 30);
    unsigned op1 = bits(i->opcode, 28, 28);
    unsigned op2 = bits(i->opcode, 21, 24);
    unsigned op3 = bits(i->opcode, 10, 15);

    if(op0 == 0 && op1 == 1 && op2 == 6)
        result = DisassembleDataProcessingTwoSourceInstr(i, out);
    else if(op0 == 1 && op1 == 1 && op2 == 6)
        result = DisassembleDataProcessingOneSourceInstr(i, out);
    else if(op1 == 0 && (op2 & ~7) == 0)
        result = DisassembleLogicalShiftedRegisterInstr(i, out);
    else if(op1 == 0 && ((op2 & ~6) == 8 || (op2 & ~6) == 9))
        result = DisassembleAddSubtractShiftedOrExtendedInstr(i, out, op2 & 1);

    return result;
    /*
    char *disassembled = NULL;

    unsigned int op3 = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int op2 = getbitsinrange(instruction->opcode, 21, 4);
    unsigned int op1 = getbitsinrange(instruction->opcode, 28, 1);
    unsigned int op0 = getbitsinrange(instruction->opcode, 30, 1);

    if(op0 == 0 && op1 == 0x1 && op2 == 0x6)
        disassembled = DisassembleDataProcessingTwoSourceInstr(instruction);
    else if(op0 == 0x1 && op1 == 0x1 && op2 == 0x6)
        disassembled = DisassembleDataProcessingOneSourceInstr(instruction);
    else if(op1 == 0 && (op2 & ~0x7) == 0)
        disassembled = DisassembleLogicalShiftedRegisterInstr(instruction);
    else if(op1 == 0 && ((op2 & ~0x6) == 0x8 || (op2 & ~0x6) == 0x9))
        disassembled = DisassembleAddSubtractShiftedOrExtendedInstr(instruction, (op2 & 1));	
    else if(op1 == 0x1 && op2 == 0 && op3 == 0)
        disassembled = DisassembleAddSubtractCarryInstr(instruction);
    else if(op1 == 0x1 && op2 == 0 && (op3 & ~0x20) == 0x1)
        disassembled = DisassembleRotateRightIntoFlagsInstr(instruction);
    else if(op1 == 0x1 && op2 == 0 && (op2 & ~0x30) == 0x2)
        disassembled = DisassembleEvaluateIntoFlagsInstr(instruction);
    else if(op1 == 0x1 && op2 == 0x2 && ((op3 & ~0x3d) == 0 || (op3 & ~0x3d) == 0x2))
        disassembled = DisassembleConditionalCompareInstr(instruction, (op3 & ~0x3d));
    else if(op1 == 0x1 && op2 == 0x4)
        disassembled = DisassembleConditionalSelectInstr(instruction);
    else if(op1 == 0x1 && (op2 >> 0x3) == 0x1)
        disassembled = DisassembleDataProcessingThreeSourceInstr(instruction);
    else
        return strdup(".undefined");

    return disassembled;
    */
}
