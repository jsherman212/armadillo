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

/*
char *DisassembleDataProcessingTwoSourceInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    // must be 64 bit in order to use PACGA
    if(opcode == 0xc && sf != 1)
        return strdup(".undefined");

    const char *instr_tbl[] = {NULL, NULL, "udiv", "sdiv", NULL, NULL, NULL, NULL, "lslv", "lsrv", "asrv", "rorv", 
        "pacga", NULL, NULL, NULL, "crc32b", "crc32h", "crc32w", "crc32x", "crc32cb",
        "crc32ch", "crc32cw", "crc32cx"};

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
        return strdup(".undefined");
    const char *instr = instr_tbl[opcode];

    if(!instr)
        return strdup(".undefined");

    const char *_Rd = registers[Rd];
    const char *_Rn = registers[Rn];
    const char *_Rm = NULL;

    if(strcmp(instr, "pacga") == 0)
        _Rm = Rm == 31 ? "sp" : ARM64_GeneralRegisters[Rm];
    else
        _Rm = registers[Rm];

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

    return disassembled;
}

char *DisassembleDataProcessingOneSourceInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int opcode2 = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    const char *_Rd = registers[Rd];
    const char *_Rn = NULL;

    if(opcode2 == 1 && opcode < 8)
        _Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];
    else
        _Rn = registers[Rn];

    if(opcode2 == 0){
        const char *instr_tbl[] = {"rbit", "rev16", "rev", NULL, "clz", "cls"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        const char *instr = instr_tbl[opcode];

        if(opcode == 2 && sf == 1)
            instr = "rev32";
        else if(opcode == 3 && sf == 1)
            instr = "rev";

        if(!instr)
            return strdup(".undefined");

        disassembled = malloc(128);
        sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);
    }
    else if(opcode2 == 1 && opcode < 8){
        const char *instr_tbl[] = {"pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        const char *instr = instr_tbl[opcode];

        disassembled = malloc(128);
        sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);
    }
    else if(opcode2 == 1 && opcode >= 8 && Rn == 0x1f){
        // sub 8 to prevent an annoying row of NULL
        opcode -= 8;

        const char *instr_tbl[] = {"paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        const char *instr = instr_tbl[opcode];

        disassembled = malloc(128);
        sprintf(disassembled, "%s %s", instr, _Rd);
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

const char *decode_shift(unsigned int op){
    switch(op){
        case 0:
            return "lsl";
        case 1:
            return "lsr";
        case 2:
            return "asr";
        case 3:
            return "ror";
        default:
            return NULL;
    };
}

char *DisassembleLogicalShiftedRegisterInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm6 = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int N = getbitsinrange(instruction->opcode, 21, 1);
    unsigned int shift = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int opc = getbitsinrange(instruction->opcode, 29, 2);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    if(sf == 0 && (imm6 >> 5) == 1)
        return strdup(".undefined");

    const char **registers = ARM64_32BitGeneralRegisters;	

    if(sf == 1)
        registers = ARM64_GeneralRegisters;

    unsigned int encoding = (sf << 3) | (opc << 1) | N;

    const char *instr_tbl[] = {"and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"};

    const char *instr = NULL;

    if(sf == 0){
        if(!check_bounds(encoding, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");

        instr = instr_tbl[encoding];
    }
    else{
        if(!check_bounds(encoding - 8, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[encoding - 8];
    }

    const char *_Rd = registers[Rd];
    const char *_Rn = registers[Rn];
    const char *_Rm = registers[Rm];

    const char *_shift = decode_shift(shift);

    disassembled = malloc(128);

    if(strcmp(instr, "orr") == 0 && shift == 0 && imm6 == 0 && Rn == 0x1f){
        sprintf(disassembled, "mov %s, %s", _Rd, _Rm);
    }
    else if(strcmp(instr, "orn") == 0 && Rn == 0x1f){
        sprintf(disassembled, "mvn %s, %s", _Rd, _Rm);

        if(shift != 0)
            sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
    }
    else if(strcmp(instr, "ands") == 0 && Rd == 0x1f){
        sprintf(disassembled, "tst %s, %s", _Rn, _Rm);

        if(shift != 0)
            sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
    }
    else{
        sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

        if(shift != 0)
            sprintf(disassembled, "%s, %s #%d", disassembled, _shift, imm6);
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

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
