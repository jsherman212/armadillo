#include <stdio.h>
#include <stdlib.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "utils.h"
#include "strext.h"

static int get_post_idx_immediate_offset(int regamount, unsigned int Q){
    if(regamount == 1)
        return Q == 0 ? 8 : 16;
    if(regamount == 2)
        return Q == 0 ? 16 : 32;
    if(regamount == 3)
        return Q == 0 ? 24 : 48;
    if(regamount == 4)
        return Q == 0 ? 32 : 64;

    return -1;
}

static int DisassembleLoadStoreMultStructuresInstr(struct instruction *i,
        struct ad_insn *out, int postidxed){
    unsigned Q = bits(i->opcode, 30, 30);
    unsigned L = bits(i->opcode, 22, 22);
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned opcode = bits(i->opcode, 12, 15);
    unsigned size = bits(i->opcode, 10, 11);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rt = bits(i->opcode, 0, 4);

    const char *T = get_arrangement(size, Q);

    if(!T)
        return 1;

    ADD_FIELD(out, Q);
    ADD_FIELD(out, L);

    if(postidxed)
        ADD_FIELD(out, Rm);

    ADD_FIELD(out, opcode);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rt);

    const char *instr_s = NULL;
    int instr_id = NONE;

    if(L == 0)
        instr_s = "st";
    else
        instr_s = "ld";

    unsigned regcnt, selem;

    switch(opcode){
        case 0: regcnt = 4; selem = 4; break;
        case 0x2: regcnt = 4; selem = 1; break;
        case 0x4: regcnt = 3; selem = 3; break;
        case 0x6: regcnt = 3; selem = 1; break;
        case 0x7: regcnt = 1; selem = 1; break;
        case 0x8: regcnt = 2; selem = 2; break;
        case 0xa: regcnt = 2; selem = 1; break;
        default: return 1;
    };

    if(L == 0)
        instr_id = (AD_INSTR_ST1 - 1) + selem;
    else
        /* the way the AD_INSTR_* enum is set up makes this more complicated */
        instr_id = (AD_INSTR_LD1 - 1) + ((selem * 2) - 1);

    concat(&DECODE_STR(out), "%s%d { ", instr_s, selem);

    for(int i=Rt; i<(Rt+regcnt)-1; i++){
        ADD_REG_OPERAND(out, i, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_FP_V_128));
        const char *Ri_s = GET_FP_REG(AD_RTBL_FP_V_128, i);

        concat(&DECODE_STR(out), "%s.%s, ", Ri_s, T);
    }

    ADD_REG_OPERAND(out, (Rt+regcnt)-1, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE),
            _RTBL(AD_RTBL_FP_V_128));
    const char *last_Rt_s = GET_FP_REG(AD_RTBL_FP_V_128, (Rt+regcnt)-1);

    ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

    concat(&DECODE_STR(out), "%s.%s }, [%s]", last_Rt_s, T, Rn_s);

    if(postidxed){
        if(Rm != 0x1f){
            ADD_REG_OPERAND(out, Rm, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                    _RTBL(AD_RTBL_GEN_64));
            const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

            concat(&DECODE_STR(out), ", %s", Rm_s);
        }
        else{
            int imm = get_post_idx_immediate_offset(regcnt, Q);

            if(imm == -1)
                return 1;

            /* imm is unsigned, that fxn returns -1 for error checking */
            ADD_IMM_OPERAND(out, AD_UINT, *(unsigned int *)&imm);

            concat(&DECODE_STR(out), ", #%#x", (unsigned)imm);
        }
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleLoadStoreSingleStructuresInstr(struct instruction *i,
        struct ad_insn *out, int postidxed){
    unsigned Q = bits(i->opcode, 30, 30);
    unsigned L = bits(i->opcode, 22, 22);
    unsigned R = bits(i->opcode, 21, 21);
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned opcode = bits(i->opcode, 13, 15);
    unsigned S = bits(i->opcode, 12, 12);
    unsigned size = bits(i->opcode, 10, 11);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rt = bits(i->opcode, 0, 4);

    ADD_FIELD(out, Q);
    ADD_FIELD(out, L);
    ADD_FIELD(out, R);

    if(postidxed)
        ADD_FIELD(out, Rm);

    ADD_FIELD(out, opcode);
    ADD_FIELD(out, S);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rt);

    const char *instr_s = NULL;
    int instr_id = NONE;

    if(L == 0)
        instr_s = "st";
    else
        instr_s = "ld";

    const char *suffix = NULL;

    unsigned scale = opcode >> 1;
    unsigned selem = (((opcode & 1) << 1) | R) + 1;
    unsigned index = 0;

    int replicate = 0;

    switch(scale){
        case 3: replicate = 1; break;
        case 0:
            {
                index = (Q << 3) | (S << 2) | size;
                suffix = "b";
                break;
            }
        case 1:
            {
                index = (Q << 2) | (S << 1) | (size >> 1);
                suffix = "h";
                break;
            }
        case 2:
            {
                if((size & 1) == 0){
                    index = (Q << 1) | S;
                    suffix = "s";
                }
                else{
                    index = Q;
                    suffix = "d";
                }

                break;
            }
        default: return 1;
    };

    if(replicate)
        instr_id = (AD_INSTR_LD1R - 1) + ((selem * 2) - 1);
    else if(L == 0)
        instr_id = (AD_INSTR_ST1 - 1) + selem;
    else if(L == 1)
        instr_id = (AD_INSTR_LD1 - 1) + ((selem * 2) - 1);

    concat(&DECODE_STR(out), "%s%d%s { ", instr_s, selem, replicate ? "r" : "");

    for(int i=Rt; i<(Rt+selem)-1; i++){
        ADD_REG_OPERAND(out, i, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_FP_V_128));
        const char *Ri_s = GET_FP_REG(AD_RTBL_FP_V_128, i);

        concat(&DECODE_STR(out), "%s", Ri_s);

        if(replicate){
            const char *T = get_arrangement(size, Q);

            if(!T)
                return 1;

            concat(&DECODE_STR(out), ".%s", T);
        }
        else{
            concat(&DECODE_STR(out), ".%s", suffix);
        }

        concat(&DECODE_STR(out), ", ");
    }

    ADD_REG_OPERAND(out, (Rt+selem)-1, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE),
            _RTBL(AD_RTBL_FP_V_128));
    const char *last_Rt_s = GET_FP_REG(AD_RTBL_FP_V_128, (Rt+selem)-1);

    concat(&DECODE_STR(out), "%s", last_Rt_s);

    if(replicate){
        const char *T = get_arrangement(size, Q);

        if(!T)
            return 1;

        concat(&DECODE_STR(out), ".%s", T);
    }
    else{
        concat(&DECODE_STR(out), ".%s", suffix);
    }

    concat(&DECODE_STR(out), " }");

    if(!replicate){
        ADD_IMM_OPERAND(out, AD_UINT, *(unsigned int *)&index);
        concat(&DECODE_STR(out), "[%d]", index);
    }

    ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

    concat(&DECODE_STR(out), ", [%s]", Rn_s);

    int rimms[] = { 1, 2, 4, 8 };

    if(postidxed){
        if(replicate){
            if(Rm != 0x1f){
                ADD_REG_OPERAND(out, Rm, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                        _RTBL(AD_RTBL_GEN_64));
                const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

                concat(&DECODE_STR(out), ", %s", Rm_s);
            }
            else{
                unsigned imm = rimms[selem] * selem;
                ADD_IMM_OPERAND(out, AD_UINT, *(unsigned int *)&imm);

                concat(&DECODE_STR(out), ", #%#x", imm);
            }
        }
        else{
            if(Rm != 0x1f){
                ADD_REG_OPERAND(out, Rm, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                        _RTBL(AD_RTBL_GEN_64));
                const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

                concat(&DECODE_STR(out), ", %s", Rm_s);
            }
            else{
                int idx = 0;

                if(*suffix == 'h')
                    idx = 1;
                else if(*suffix == 's')
                    idx = 2;
                else if(*suffix == 'd')
                    idx = 3;

                unsigned imm = rimms[idx] * selem;
                ADD_IMM_OPERAND(out, AD_UINT, *(unsigned int *)&imm);

                concat(&DECODE_STR(out), ", #%#x", imm);
            }
        }
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleLoadStoreMemoryTagsInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned opc = bits(i->opcode, 22, 23);
    unsigned imm9 = bits(i->opcode, 12, 20);
    unsigned op2 = bits(i->opcode, 10, 11);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rt = bits(i->opcode, 0, 4);

    if((opc == 2 || opc == 3) && imm9 != 0 && op2 == 0)
        return 1;

    ADD_FIELD(out, opc);
    ADD_FIELD(out, imm9);
    ADD_FIELD(out, op2);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rt);

    int instr_id = NONE;

    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rt_s = GET_GEN_REG(AD_RTBL_GEN_64, Rt, NO_PREFER_ZR);

    if((opc == 0 || opc == 2 || opc == 3) && imm9 == 0 && op2 == 0){
        const char *instr_s = NULL;

        if(opc == 0){
            instr_s = "stzgm";
            instr_id = AD_INSTR_STZGM;
        }
        else if(opc == 2){
            instr_s = "stgm";
            instr_id = AD_INSTR_STGM;
        }
        else{
            instr_s = "ldgm";
            instr_id = AD_INSTR_LDGM;
        }

        ADD_REG_OPERAND(out, Rt, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));
        ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));

        concat(&DECODE_STR(out), "%s %s, [%s]", instr_s, Rt_s, Rn_s);
    }
    else if(opc == 1 && op2 == 0){
        instr_id = AD_INSTR_LDG;

        ADD_REG_OPERAND(out, Rt, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));
        ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));

        concat(&DECODE_STR(out), "ldg %s, [%s", Rt_s, Rn_s);

        if(imm9 != 0){
            signed simm = sign_extend(imm9, 9) << 4;

            ADD_IMM_OPERAND(out, AD_INT, *(int *)&simm);

            concat(&DECODE_STR(out), ", #"S_X"", S_A(simm));
        }

        concat(&DECODE_STR(out), "]");
    }
    else if(op2 > 0){
        enum {
            post = 1, signed_ = 2, pre
        };

        const char *instr_s = NULL;

        if(opc == 0){
            instr_s = "stg";
            instr_id = AD_INSTR_STG;
        }
        else if(opc == 1){
            instr_s = "stzg";
            instr_id = AD_INSTR_STZG;
        }
        else if(opc == 2){
            instr_s = "st2g";
            instr_id = AD_INSTR_ST2G;
        }
        else if(opc == 3){
            instr_s = "stz2g";
            instr_id = AD_INSTR_STZ2G;
        }

        ADD_REG_OPERAND(out, Rt, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));
        ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_GEN_64));

        concat(&DECODE_STR(out), "%s %s, [%s", instr_s, Rt_s, Rn_s);

        if(imm9 == 0)
            concat(&DECODE_STR(out), "]");
        else{
            signed simm = sign_extend(imm9, 9) << 4;

            ADD_IMM_OPERAND(out, AD_INT, *(int *)&simm);

            if(op2 == post)
                concat(&DECODE_STR(out), "], #"S_X"", S_A(simm));
            else{
                concat(&DECODE_STR(out), ", #"S_X"]", S_A(simm));

                if(op2 == pre)
                    concat(&DECODE_STR(out), "!");
            }
        }
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleLoadAndStoreExclusiveInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned size = bits(i->opcode, 30, 31);
    unsigned o2 = bits(i->opcode, 23, 23);
    unsigned L = bits(i->opcode, 22, 22);
    unsigned o1 = bits(i->opcode, 21, 21);
    unsigned Rs = bits(i->opcode, 16, 20);
    unsigned o0 = bits(i->opcode, 15, 15);
    unsigned Rt2 = bits(i->opcode, 10, 14);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rt = bits(i->opcode, 0, 4);

    ADD_FIELD(out, size);
    ADD_FIELD(out, o2);
    ADD_FIELD(out, L);
    ADD_FIELD(out, o1);
    ADD_FIELD(out, Rs);
    ADD_FIELD(out, o0);
    ADD_FIELD(out, Rt2);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rt);

    unsigned encoding = (o2 << 3) | (L << 2) | (o1 << 1) | o0;
    int instr_id = NONE;

    if(Rt2 == 0x1f){
        if((size == 0 || size == 1) && (encoding == 2 || encoding == 3 ||
                    encoding == 6 || encoding == 7)){
            unsigned sz = size & 1;
            const char **registers = AD_RTBL_GEN_32;

            if(sz == 1)
                registers = AD_RTBL_GEN_64;

            int rsz = (registers == AD_RTBL_GEN_64 ? _64_BIT : _32_BIT);

            const char *Rs_s = GET_GEN_REG(registers, Rs, PREFER_ZR);
            const char *Rs1_s = GET_GEN_REG(registers, Rs + 1, PREFER_ZR);
            const char *Rt_s = GET_GEN_REG(registers, Rt, PREFER_ZR);
            const char *Rt1_s = GET_GEN_REG(registers, Rt + 1, PREFER_ZR);

            /* always 64 bit */
            const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

            ADD_REG_OPERAND(out, Rs, rsz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rs + 1, rsz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rt, rsz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
            ADD_REG_OPERAND(out, Rt + 1, rsz, PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

            ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));

            const char *instr_s = NULL;

            if(encoding == 2){
                instr_s = "casp";
                instr_id = AD_INSTR_CASP;
            }
            else if(encoding == 3){
                instr_s = "caspl";
                instr_id = AD_INSTR_CASPL;
            }
            else if(encoding == 6){
                instr_s = "caspa";
                instr_id = AD_INSTR_CASPA;
            }
            else{
                instr_s = "caspal";
                instr_id = AD_INSTR_CASPAL;
            }

            concat(&DECODE_STR(out), "%s %s, %s, %s, %s, [%s]", instr_s,
                    Rs_s, Rs1_s, Rt_s, Rt1_s, Rn_s);
        }
        else if((size == 0 || size == 1 || size == 2 || size == 3) &&
                (encoding == 10 || encoding == 11 || encoding == 14 || encoding == 15)){
            const char **Rs_Rt_Rtbl = AD_RTBL_GEN_32;
            unsigned Rs_Rt_Sz = _32_BIT;

            if(size == 3){
                Rs_Rt_Rtbl = AD_RTBL_GEN_64;
                Rs_Rt_Sz = _64_BIT;
            }

            const char *Rs_s = GET_GEN_REG(Rs_Rt_Rtbl, Rs, PREFER_ZR);
            const char *Rt_s = GET_GEN_REG(Rs_Rt_Rtbl, Rt, PREFER_ZR);
            const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

            ADD_REG_OPERAND(out, Rs, Rs_Rt_Sz, NO_PREFER_ZR, _SYSREG(NONE), Rs_Rt_Rtbl);
            ADD_REG_OPERAND(out, Rt, Rs_Rt_Sz, NO_PREFER_ZR, _SYSREG(NONE), Rs_Rt_Rtbl);
            ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));

            const char *instr_s = NULL;

            if(encoding == 10){
                instr_s = "cas";
                instr_id = AD_INSTR_CASB;
            }
            else if(encoding == 11){
                instr_s = "casl";
                instr_id = AD_INSTR_CASLB;
            }
            else if(encoding == 14){
                instr_s = "casa";
                instr_id = AD_INSTR_CASAB;
            }
            else{
                instr_s = "casal";
                instr_id = AD_INSTR_CASALB;
            }

            const char *suffix = NULL; 

            if(size == 0)
                suffix = "b";
            else if(size == 1){
                instr_id += 4;
                suffix = "h";
            }
            else{
                if(encoding == 10)
                    instr_id += 10;
                else if(encoding == 11)
                    instr_id += 12;
                else
                    instr_id += 13;

                suffix = "";
            }

            concat(&DECODE_STR(out), "%s%s %s, %s, [%s]", instr_s, suffix,
                    Rs_s, Rt_s, Rn_s);
        }
    }
    else if(size == 0 || size == 1){
        /* We'll figure out if this deals with bytes or halfwords later.
         * For now, set the instruction id to the instruction which deals with
         * bytes, and if we find out this instruction actually deals
         * with halfwords, we increment the instruction ID. Addtionally,
         * we'll add the last character to the instruction string later on.
         */
        struct itab tab[] = {
            { "stxr", AD_INSTR_STXRB },
            { "stlxr", AD_INSTR_STLXRB },
            { NULL, NONE },
            { NULL, NONE },
            { "ldxr", AD_INSTR_LDXRB },
            { "ldaxr", AD_INSTR_LDAXRB },
            { NULL, NONE },
            { NULL, NONE },
            { "stllr", AD_INSTR_STLLRB },
            { "stlr", AD_INSTR_STLRB },
            { NULL, NONE },
            { NULL, NONE },
            { "ldlar", AD_INSTR_LDLARB },
            { "ldar", AD_INSTR_LDARB },
        };

        const char *instr_s = tab[encoding].instr_s;
        instr_id = tab[encoding].instr_id;

        /* insn deals with bytes */
        if(size == 0)
            concat(&DECODE_STR(out), "%sb", instr_s);
        else{
            concat(&DECODE_STR(out), "%sh", instr_s);

            instr_id++;
        }


        /*
        if(encoding == 0 || encoding == 1){
            const char *Rs_s = GET_GEN_REG(AD_RTBL_GEN_32, Rs, PREFER_ZR);
            const char *Rt_s = GET_GEN_REG(AD_RTBL_GEN_32, Rt, PREFER_ZR);
            const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

            ADD_REG_OPERAND(out, Rs, _SZ(_32_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_32));
            ADD_REG_OPERAND(out, Rt, _SZ(_32_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_32));
            ADD_REG_OPERAND(out, Rn, _SZ(_64_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_GEN_64));

            const char *instr_s = NULL;

        }
        */

    }


    SET_INSTR_ID(out, instr_id);

    /*
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int Rt2 = getbitsinrange(instruction->opcode, 10, 5);
    unsigned int o0 = getbitsinrange(instruction->opcode, 15, 1);
    unsigned int Rs = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int o1 = getbitsinrange(instruction->opcode, 21, 1);
    unsigned int L = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int o2 = getbitsinrange(instruction->opcode, 23, 1);
    unsigned int size = getbitsinrange(instruction->opcode, 30, 2);
    unsigned int sz = getbitsinrange(instruction->opcode, 30, 1);

    unsigned int encoding = (o2 << 3) | (L << 2) | (o1 << 1) | o0;

    const char **registers = ARM64_32BitGeneralRegisters;

    if(size == 3)
        registers = ARM64_GeneralRegisters;

    disassembled = malloc(128);
    sprintf(disassembled, ".unknown");

    if(encoding == 0){
        // another stxr in case it is the 64 bit version
        const char *instr_tbl[] = {"stxrb", "stxrh", "stxr", "stxr"};

        const char *_Rs = ARM64_32BitGeneralRegisters[Rs];
        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, %s, [%s]", instr_tbl[size], _Rs, _Rt, _Rn);
    }
    else if(encoding == 1){
        const char *instr_tbl[] = {"stlxrb", "stlxrh", "stlxr", "stlxr"};

        const char *_Rs = ARM64_32BitGeneralRegisters[Rs];
        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, %s, [%s]", instr_tbl[size], _Rs, _Rt, _Rn);
    }
    else if(encoding == 2 || encoding == 3){
        const char *_Rs = ARM64_32BitGeneralRegisters[Rs];
        const char *_Rt1 = registers[Rt];
        const char *_Rt2 = registers[Rt2];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, %s, %s, [%s]", encoding == 2 ? "stxp" : "stlxp", _Rs, _Rt1, _Rt2, _Rn);
    }
    else if(encoding == 4){
        const char *instr_tbl[] = {"ldxrb", "ldxrh", "ldxr", "ldxr"};

        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
    }
    else if(encoding == 5){
        const char *instr_tbl[] = {"ldaxrb", "ldaxrh", "ldaxr", "ldaxr"};

        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
    }
    else if(encoding == 6 || encoding == 7){
        if(Rt2 == 0x1f){
            if(sz == 1)
                registers = ARM64_GeneralRegisters;

            const char *_Rs = registers[Rs];
            const char *_Rs2 = registers[Rs + 1];
            const char *_Rt = registers[Rt];
            const char *_Rt2 = registers[Rt + 1];
            const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

            sprintf(disassembled, "%s %s, %s, %s, %s, [%s]", encoding == 6 ? "caspa" : "caspal", _Rs, _Rs2, _Rt, _Rt2, _Rn);
        }
        else{
            const char *_Rt1 = registers[Rt];
            const char *_Rt2 = registers[Rt2];
            const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

            sprintf(disassembled, "%s %s, %s, [%s]", encoding == 6 ? "ldxp" : "ldaxp", _Rt1, _Rt2, _Rn);
        }
    }
    else if(encoding == 8){
        const char *instr_tbl[] = {"stllrb", "stllrh", "stllr", "stllr"};

        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
    }
    else if(encoding == 9){
        const char *instr_tbl[] = {"stlrb", "stlrh", "stlr", "stlr"};

        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
    }
    else if((encoding == 10 || encoding == 11 || encoding == 14 || encoding == 15) && Rt2 == 0x1f){
        const char **registers = ARM64_32BitGeneralRegisters;

        if(size == 3)
            registers = ARM64_GeneralRegisters;

        const char *_Rs = registers[Rs];
        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        const char *instr = size == 1 ? "cash" : "cas";

        if(encoding == 11)
            instr = (size == 2 || size == 3) ? "casl" : "caslh";
        else if(encoding == 14)
            instr = (size == 2 || size == 3) ? "casa" : "casah";
        else if(encoding == 15)
            instr = (size == 2 || size == 3) ? "casal" : "casalh";

        sprintf(disassembled, "%s %s, %s, [%s]", instr, _Rs, _Rt, _Rn);
    }
    else if(encoding == 12){
        const char *instr_tbl[] = {"ldlarb", "ldlarh", "ldlar", "ldlar"};

        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
    }
    else if(encoding == 13){
        const char *instr_tbl[] = {"ldarb", "ldarh", "ldar", "ldar"};

        const char *_Rt = registers[Rt];
        const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

        sprintf(disassembled, "%s %s, [%s]", instr_tbl[size], _Rt, _Rn);
    }
    */

    return 0;
}

/*
char *DisassembleLoadAndStoreLiteralInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int imm19 = getbitsinrange(instruction->opcode, 5, 19);
    unsigned int V = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int opc = getbitsinrange(instruction->opcode, 30, 2);

    if(opc == 3 && V == 1)
        return strdup(".undefined");

    const char **general_registers = ARM64_GeneralRegisters;
    const char **flt_registers = ARM64_VectorQRegisters;

    if(opc == 0){
        general_registers = ARM64_32BitGeneralRegisters;
        flt_registers = ARM64_VectorSinglePrecisionRegisters;
    }
    else if(opc == 1)
        flt_registers = ARM64_VectorDoublePrecisionRegisters;

    if(opc == 3 && V == 0){
        disassembled = malloc(128);

        const char *types[] = {"PLD", "PLI", "PST"};
        const char *targets[] = {"L1", "L2", "L3"};
        const char *policies[] = {"KEEP", "STRM"};

        unsigned int type = getbitsinrange(Rt, 3, 1);
        unsigned int target = getbitsinrange(Rt, 1, 1);
        unsigned int policy = Rt & 1;

        imm19 = sign_extend(imm19, 19);

        if(type > 2 || target > 2 || policy > 1)
            sprintf(disassembled, "prfm #%#x, #%#lx", Rt, (signed int)imm19 + instruction->PC);
        else
            sprintf(disassembled, "prfm %s%s%s, #%#lx", types[type], targets[target], policies[policy], (signed int)imm19 + instruction->PC);
    }
    else{
        const char *instr = "ldr";

        if(opc == 2 && V == 0)
            instr = "ldrsw";

        if(V == 0){
            disassembled = malloc(128);

            imm19 = sign_extend((imm19 << 2), 21);

            sprintf(disassembled, "%s %s, #%#lx", instr, general_registers[Rt], (signed int)imm19 + instruction->PC);
        }
        else{
            disassembled = malloc(128);

            imm19 = sign_extend((imm19 << 2), 21);

            sprintf(disassembled, "%s %s, #%#lx", instr, flt_registers[Rt], (signed int)imm19 + instruction->PC);
        }
    }

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleLoadAndStoreRegisterPairInstr(struct instruction *instruction, int kind){
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int Rt2 = getbitsinrange(instruction->opcode, 10, 5);
    int imm7 = getbitsinrange(instruction->opcode, 15, 7);
    unsigned int L = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int V = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int opc = getbitsinrange(instruction->opcode, 30, 2);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(opc == 0)
        registers = V == 0 ? registers : ARM64_VectorSinglePrecisionRegisters;
    else if(opc == 1)
        registers = V == 0 ? ARM64_GeneralRegisters : ARM64_VectorDoublePrecisionRegisters;
    else if(opc == 2)
        registers = V == 0 ? ARM64_GeneralRegisters : ARM64_VectorQRegisters;

    disassembled = malloc(128);

    int scale = 0;

    // if V is 0, we're not dealing with floating point registers
    if(V == 0)
        scale = 2 + (opc >> 1);
    else
        scale = 2 + opc;

    imm7 = sign_extend(imm7, 7) << scale;

    char *instr = malloc(8);
    sprintf(instr, "st");

    if(L == 1)
        sprintf(instr, "%s", (V == 0 && opc == 1) ? "ldpsw" : "ld");

    if(strcmp(instr, "ldpsw") != 0)
        sprintf(instr, "%s%sp", instr, kind == NO_ALLOCATE ? "n" : "");

    const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

    sprintf(disassembled, "%s %s, %s, [%s", instr, registers[Rt], registers[Rt2], _Rn);
    free(instr);

    // check whether or not we need to append an immediate
    if(imm7 == 0)
        sprintf(disassembled, "%s]", disassembled);
    else if(kind == POST_INDEXED)
        sprintf(disassembled, "%s], #%s%#x", disassembled, imm7 < 0 ? "-" : "", imm7 < 0 ? -imm7 : imm7);
    else if(kind == OFFSET || kind == NO_ALLOCATE)
        sprintf(disassembled, "%s, #%s%#x]", disassembled, imm7 < 0 ? "-" : "", imm7 < 0 ? -imm7 : imm7);
    else if(kind == PRE_INDEXED)
        sprintf(disassembled, "%s, #%s%#x]!", disassembled, imm7 < 0 ? "-" : "", imm7 < 0 ? -imm7 : imm7);

    return disassembled;
}

char *DisassembleLoadAndStoreRegisterInstr(struct instruction *instruction, int kind){
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    int imm12 = getbitsinrange(instruction->opcode, 10, 12);
    int imm9 = imm12 >> 2;
    unsigned int opc = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int V = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int size = getbitsinrange(instruction->opcode, 30, 2);

    const char **registers = ARM64_32BitGeneralRegisters;

    if(V == 0 && (opc == 2 || size == 3))
        registers = ARM64_GeneralRegisters;
    else if(V == 1){
        if(size == 0 && (opc == 0 || opc == 1))
            registers = ARM64_VectorBRegisters;
        else if(size == 0 && (opc == 2 || opc == 3))
            registers = ARM64_VectorQRegisters;
        else if(size == 1 && (opc == 0 || opc == 1))
            registers = ARM64_VectorHalfPrecisionRegisters;
        else if(size == 2 && (opc == 0 || opc == 1))
            registers = ARM64_VectorSinglePrecisionRegisters;
        else if(size == 3 && (opc == 0 || opc == 1))
            registers = ARM64_VectorDoublePrecisionRegisters;
    }

    unsigned int instr_idx = (size << 3) | (V << 2) | opc;

    const char **instr_tbl = unscaled_instr_tbl;

    if(kind == UNSIGNED_IMMEDIATE || kind == IMMEDIATE_POST_INDEXED || kind == IMMEDIATE_PRE_INDEXED){
        if(!check_bounds(instr_idx, ARRAY_SIZE(pre_post_unsigned_register_idx_instr_tbl)))
            return strdup(".undefined");

        instr_tbl = pre_post_unsigned_register_idx_instr_tbl;
    }
    else if(kind == UNPRIVILEGED){
        if(!check_bounds(instr_idx, ARRAY_SIZE(unprivileged_instr_tbl)))
            return strdup(".undefined");
        instr_tbl = unprivileged_instr_tbl;
    }
    else{
        if(!check_bounds(instr_idx, ARRAY_SIZE(unscaled_instr_tbl)))
            return strdup(".undefined");
    }

    const char *instr = instr_tbl[instr_idx];

    if(!instr)
        return strdup(".undefined");

    imm9 = sign_extend(imm9, 9);

    disassembled = malloc(128);

    const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

    if(strcmp(instr, "prfm") == 0){
        const char *types[] = {"PLD", "PLI", "PST"};
        const char *targets[] = {"L1", "L2", "L3"};
        const char *policies[] = {"KEEP", "STRM"};

        unsigned int type = getbitsinrange(Rt, 3, 1);
        unsigned int target = getbitsinrange(Rt, 1, 1);
        unsigned int policy = Rt & 1;

        if(type > 2 || target > 2 || policy > 1)
            sprintf(disassembled, "%s #%#x, #%#lx", instr, Rt, imm9 + instruction->PC);
        else
            sprintf(disassembled, "%s %s%s%s, #%#lx", instr, types[type], targets[target], policies[policy], imm9 + instruction->PC);

        return disassembled;
    }

    sprintf(disassembled, "%s %s, [%s", instr, registers[Rt], _Rn);

    if(kind == UNSCALED_IMMEDIATE || kind == UNPRIVILEGED){
        if(imm9 == 0)
            sprintf(disassembled, "%s]", disassembled);
        else
            sprintf(disassembled, "%s, #%s%#x]", disassembled, imm9 < 0 ? "-" : "", imm9 < 0 ? -imm9 : imm9);
    }
    else if(kind == UNSIGNED_IMMEDIATE){
        imm12 = sign_extend(imm12, 12);

        if(imm12 == 0)
            sprintf(disassembled, "%s]", disassembled);
        else{
            if((opc >> 1) == 0)
                imm12 <<= ((opc >> 1) | size);

            sprintf(disassembled, "%s, #%s%#x]", disassembled, imm12 < 0 ? "-" : "", imm12 < 0 ? -imm12 : imm12);
        }
    }
    else if(kind == IMMEDIATE_POST_INDEXED)
        sprintf(disassembled, "%s], #%s%#x", disassembled, imm9 < 0 ? "-" : "", imm9 < 0 ? -imm9 : imm9);
    else if(kind == IMMEDIATE_PRE_INDEXED)
        sprintf(disassembled, "%s, #%s%#x]!", disassembled, imm9 < 0 ? "-" : "", imm9 < 0 ? -imm9 : imm9);

    return disassembled;
}

char *get_atomic_memory_instr(unsigned int size, unsigned int V, unsigned int A, unsigned int R, unsigned int o3, unsigned int opc){
    unsigned int encoding = size << 7;
    encoding |= V << 6;
    encoding |= A << 5;
    encoding |= R << 4;
    encoding |= o3 << 3;
    encoding |= opc;

    // auto generated
    // [a-zA-Z0-9]+(?=\s?variant)
    switch(encoding){
        case 0x0:
            return "ldaddb";
        case 0x1:
            return "ldclrb";
        case 0x2:
            return "ldeorb";
        case 0x3:
            return "ldsetb";
        case 0x4:
            return "ldsmaxb";
        case 0x5:
            return "ldsminb";
        case 0x6:
            return "ldumaxb";
        case 0x7:
            return "lduminb";
        case 0x8:
            return "swpb";
        case 0x10:
            return "ldaddlb";
        case 0x11:
            return "ldclrlb";
        case 0x12:
            return "ldeorlb";
        case 0x13:
            return "ldsetlb";
        case 0x14:
            return "ldsmaxlb";
        case 0x15:
            return "ldsminlb";
        case 0x16:
            return "ldumaxlb";
        case 0x17:
            return "lduminlb";
        case 0x18:
            return "swplb";
        case 0x20:
            return "ldaddab";
        case 0x21:
            return "ldclrab";
        case 0x22:
            return "ldeorab";
        case 0x23:
            return "ldsetab";
        case 0x24:
            return "ldsmaxab";
        case 0x25:
            return "ldsminab";
        case 0x26:
            return "ldumaxab";
        case 0x27:
            return "lduminab";
        case 0x28:
            return "swpab";
        case 0x2c:
            return "ldaprb";
        case 0x30:
            return "ldaddalb";
        case 0x31:
            return "ldclralb";
        case 0x32:
            return "ldeoralb";
        case 0x33:
            return "ldsetalb";
        case 0x34:
            return "ldsmaxalb";
        case 0x35:
            return "ldsminalb";
        case 0x36:
            return "ldumaxalb";
        case 0x37:
            return "lduminalb";
        case 0x38:
            return "swpalb";
        case 0x80:
            return "ldaddh";
        case 0x81:
            return "ldclrh";
        case 0x82:
            return "ldeorh";
        case 0x83:
            return "ldseth";
        case 0x84:
            return "ldsmaxh";
        case 0x85:
            return "ldsminh";
        case 0x86:
            return "ldumaxh";
        case 0x87:
            return "lduminh";
        case 0x88:
            return "swph";
        case 0x90:
            return "ldaddlh";
        case 0x91:
            return "ldclrlh";
        case 0x92:
            return "ldeorlh";
        case 0x93:
            return "ldsetlh";
        case 0x94:
            return "ldsmaxlh";
        case 0x95:
            return "ldsminlh";
        case 0x96:
            return "ldumaxlh";
        case 0x97:
            return "lduminlh";
        case 0x98:
            return "swplh";
        case 0xa0:
            return "ldaddah";
        case 0xa1:
            return "ldclrah";
        case 0xa2:
            return "ldeorah";
        case 0xa3:
            return "ldsetah";
        case 0xa4:
            return "ldsmaxah";
        case 0xa5:
            return "ldsminah";
        case 0xa6:
            return "ldumaxah";
        case 0xa7:
            return "lduminah";
        case 0xa8:
            return "swpah";
        case 0xac:
            return "ldaprh";
        case 0xb0:
            return "ldaddalh";
        case 0xb1:
            return "ldclralh";
        case 0xb2:
            return "ldeoralh";
        case 0xb3:
            return "ldsetalh";
        case 0xb4:
            return "ldsmaxalh";
        case 0xb5:
            return "ldsminalh";
        case 0xb6:
            return "ldumaxalh";
        case 0xb7:
            return "lduminalh";
        case 0xb8:
            return "swpalh";
        case 0x100:
            return "ldadd";
        case 0x101:
            return "ldclr";
        case 0x102:
            return "ldeor";
        case 0x103:
            return "ldset";
        case 0x104:
            return "ldsmax";
        case 0x105:
            return "ldsmin";
        case 0x106:
            return "ldumax";
        case 0x107:
            return "ldumin";
        case 0x108:
            return "swp";
        case 0x110:
            return "ldaddl";
        case 0x111:
            return "ldclrl";
        case 0x112:
            return "ldeorl";
        case 0x113:
            return "ldsetl";
        case 0x114:
            return "ldsmaxl";
        case 0x115:
            return "ldsminl";
        case 0x116:
            return "ldumaxl";
        case 0x117:
            return "lduminl";
        case 0x118:
            return "swpl";
        case 0x120:
            return "ldadda";
        case 0x121:
            return "ldclra";
        case 0x122:
            return "ldeora";
        case 0x123:
            return "ldseta";
        case 0x124:
            return "ldsmaxa";
        case 0x125:
            return "ldsmina";
        case 0x126:
            return "ldumaxa";
        case 0x127:
            return "ldumina";
        case 0x128:
            return "swpa";
        case 0x12c:
            return "ldapr";
        case 0x130:
            return "ldaddal";
        case 0x131:
            return "ldclral";
        case 0x132:
            return "ldeoral";
        case 0x133:
            return "ldsetal";
        case 0x134:
            return "ldsmaxal";
        case 0x135:
            return "ldsminal";
        case 0x136:
            return "ldumaxal";
        case 0x137:
            return "lduminal";
        case 0x138:
            return "swpal";
        case 0x180:
            return "ldadd";
        case 0x181:
            return "ldclr";
        case 0x182:
            return "ldeor";
        case 0x183:
            return "ldset";
        case 0x184:
            return "ldsmax";
        case 0x185:
            return "ldsmin";
        case 0x186:
            return "ldumax";
        case 0x187:
            return "ldumin";
        case 0x188:
            return "swp";
        case 0x190:
            return "ldaddl";
        case 0x191:
            return "ldclrl";
        case 0x192:
            return "ldeorl";
        case 0x193:
            return "ldsetl";
        case 0x194:
            return "ldsmaxl";
        case 0x195:
            return "ldsminl";
        case 0x196:
            return "ldumaxl";
        case 0x197:
            return "lduminl";
        case 0x198:
            return "swpl";
        case 0x1a0:
            return "ldadda";
        case 0x1a1:
            return "ldclra";
        case 0x1a2:
            return "ldeora";
        case 0x1a3:
            return "ldseta";
        case 0x1a4:
            return "ldsmaxa";
        case 0x1a5:
            return "ldsmina";
        case 0x1a6:
            return "ldumaxa";
        case 0x1a7:
            return "ldumina";
        case 0x1a8:
            return "swpa";
        case 0x1ac:
            return "ldapr";
        case 0x1b0:
            return "ldaddal";
        case 0x1b1:
            return "ldclral";
        case 0x1b2:
            return "ldeoral";
        case 0x1b3:
            return "ldsetal";
        case 0x1b4:
            return "ldsmaxal";
        case 0x1b5:
            return "ldsminal";
        case 0x1b6:
            return "ldumaxal";
        case 0x1b7:
            return "lduminal";
        case 0x1b8:
            return "swpal";
        default:
            return NULL;
    };
}

char *DisassembleAtomicMemoryInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opc = getbitsinrange(instruction->opcode, 12, 3);
    unsigned int o3 = getbitsinrange(instruction->opcode, 15, 1);
    unsigned int Rs = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int R = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int A = getbitsinrange(instruction->opcode, 23, 1);
    unsigned int V = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int size = getbitsinrange(instruction->opcode, 30, 2);

    const char *instr = get_atomic_memory_instr(size, V, A, R, o3, opc);

    if(!instr)
        return strdup(".undefined");

    const char **registers = ARM64_32BitGeneralRegisters;

    if(size == 3)
        registers = ARM64_GeneralRegisters;

    const char *_Rs = registers[Rs];
    const char *_Rt = registers[Rt];
    const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

    disassembled = malloc(128);

    if(strcmp(instr, "ldapr") != 0 && strcmp(instr, "ldaprb") != 0 && strcmp(instr, "ldaprh") != 0)
        sprintf(disassembled, "%s %s, %s, [%s]", instr, _Rs, _Rt, _Rn);
    else
        sprintf(disassembled, "%s %s, [%s]", instr, _Rt, _Rn);

    return disassembled;
}

char *DisassembleLoadAndStoreRegisterOffsetInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int S = getbitsinrange(instruction->opcode, 12, 1);
    unsigned int option = getbitsinrange(instruction->opcode, 13, 3);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int opc = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int V = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int size = getbitsinrange(instruction->opcode, 30, 2);

    const char **general_registers = ARM64_32BitGeneralRegisters;
    const char **flt_registers = ARM64_VectorQRegisters;

    int _64bit = 0;
    int amount = 0;

    // default to 128 bit
    int flt_amount = S == 0 ? 0 : 4;

    if(V == 0 && (opc == 2 || size == 3)){
        general_registers = ARM64_GeneralRegisters;
        _64bit = 1;
    }
    else if(V == 1){
        if(size == 0 && opc != 2){
            flt_registers = ARM64_VectorBRegisters;

            // this doesn't matter here
            flt_amount = -1;
        }
        else if(size == 1){
            flt_registers = ARM64_VectorHalfPrecisionRegisters;
            flt_amount = S == 0 ? 0 : 1;
        }
        else if(size == 2){
            flt_registers = ARM64_VectorSinglePrecisionRegisters;
            flt_amount = S == 0 ? 0 : 2;
        }
        else if(size == 3){
            flt_registers = ARM64_VectorDoublePrecisionRegisters;
            flt_amount = S == 0 ? 0 : 3;
        }
    }

    const char *_Rt = NULL;

    if(V == 1)
        _Rt = flt_registers[Rt];
    else
        _Rt = general_registers[Rt];

    const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];
    const char *_Rm = ARM64_32BitGeneralRegisters[Rm];

    if((option & 1) == 1)
        _Rm = ARM64_GeneralRegisters[Rm];

    int extended = option != 3 ? 1 : 0;
    const char *extend = NULL;

    if(extended)
        extend = decode_reg_extend(option);

    const char **instr_tbl = pre_post_unsigned_register_idx_instr_tbl;

    unsigned int instr_idx = (size << 3) | (V << 2) | opc;
    if(!check_bounds(instr_idx, ARRAY_SIZE(pre_post_unsigned_register_idx_instr_tbl)))
        return strdup(".undefined");
    const char *instr = instr_tbl[instr_idx];

    if(!instr)
        return strdup(".undefined");

    int omit_amount = -1;

    disassembled = malloc(128);
    sprintf(disassembled, "%s %s, [%s, %s", instr, _Rt, _Rn, _Rm);

    omit_amount = S == 0 ? 1 : 0;

    if(V == 0){
        amount = S;

        if(strcmp(instr, "strb") == 0 || strcmp(instr, "ldrb") == 0 || strcmp(instr, "ldrsb") == 0){
            if(omit_amount){
                if(extended)
                    sprintf(disassembled, "%s, %s]", disassembled, extend);
                else
                    sprintf(disassembled, "%s]", disassembled);
            }
            else if(!omit_amount){
                if(extended)
                    sprintf(disassembled, "%s, %s #%d]", disassembled, extend, amount);
                else
                    sprintf(disassembled, "%s, lsl #0]", disassembled);
            }

            return disassembled;
        }
        else if(strcmp(instr, "str") == 0 || strcmp(instr, "ldr") == 0){
            if(_64bit)
                amount = S == 0 ? 0 : 3;
            else
                amount = S == 0 ? 0 : 2;
        }
        else if(strcmp(instr, "ldrsw") == 0)
            amount = S == 0 ? 0 : 2;

        if(extended){
            sprintf(disassembled, "%s, %s", disassembled, extend);

            if(amount != 0)
                sprintf(disassembled, "%s #%d]", disassembled, amount);
            else
                sprintf(disassembled, "%s]", disassembled);
        }
        else{
            if(amount != 0)
                sprintf(disassembled, "%s, lsl #%d]", disassembled, amount);
            else
                sprintf(disassembled, "%s]", disassembled);
        }

        return disassembled;
    }
    else if(V == 1){
        if(flt_amount == -1){
            if(omit_amount){
                if(extended)
                    sprintf(disassembled, "%s, %s]", disassembled, extend);
                else
                    sprintf(disassembled, "%s]", disassembled);
            }
            else if(!omit_amount){
                if(extended)
                    sprintf(disassembled, "%s, %s #%d]", disassembled, extend, flt_amount);
                else
                    sprintf(disassembled, "%s, lsl #0]", disassembled);
            }
        }
        else if(extended){
            sprintf(disassembled, "%s, %s", disassembled, extend);

            if(flt_amount != 0)
                sprintf(disassembled, "%s #%d]", disassembled, flt_amount);
            else
                sprintf(disassembled, "%s]", disassembled);
        }
        else if(!extended){
            if(flt_amount != 0)
                sprintf(disassembled, "%s, lsl #%d]", disassembled, flt_amount);
            else
                sprintf(disassembled, "%s]", disassembled);
        }

        return disassembled;
    }

    return disassembled;
}

char *DisassembleLoadAndStorePACInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rt = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int W = getbitsinrange(instruction->opcode, 11, 1);
    unsigned int imm9 = getbitsinrange(instruction->opcode, 12, 9);
    unsigned int S = getbitsinrange(instruction->opcode, 22, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 23, 1);
    unsigned int V = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int size = getbitsinrange(instruction->opcode, 30, 2);

    if(size != 3)
        return strdup(".undefined");

    int use_key_A = M == 0;
    int S10 = (S << 9) | imm9;

    S10 = sign_extend(S10, 10);
    S10 <<= 3;

    char *instr = malloc(8);
    sprintf(instr, "ldra");

    if(use_key_A)
        strcat(instr, "a");
    else
        strcat(instr, "b");

    const char *_Rt = ARM64_GeneralRegisters[Rt];
    const char *_Rn = Rn == 31 ? "sp" : ARM64_GeneralRegisters[Rn];

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, [%s, #%s%#x]%s", instr, _Rt, _Rn, S10 < 0 ? "-" : "", S10 < 0 ? -S10 : S10, W == 1 ? "!" : "");

    free(instr);	

    return disassembled;
}
*/

int LoadsAndStoresDisassemble(struct instruction *i, struct ad_insn *out){
    int result = 0;

    unsigned op0 = bits(i->opcode, 28, 31);
    unsigned op1 = bits(i->opcode, 26, 26);
    unsigned op2 = bits(i->opcode, 23, 24);
    unsigned op3 = bits(i->opcode, 16, 21);
    unsigned op4 = bits(i->opcode, 10, 11);

    if((op0 & ~4) == 0 && op1 == 1 && (op2 == 0 || op2 == 1) && (op3 & ~0x1f) == 0)
        result = DisassembleLoadStoreMultStructuresInstr(i, out, op2);
    else if((op0 & ~4) == 0 && op1 == 1 && (op2 == 2 || op2 == 3))
        result = DisassembleLoadStoreSingleStructuresInstr(i, out, op2 != 2);
    else if(op0 == 13 && op1 == 0 && (op2 >> 1) == 1 && (op3 >> 5) == 1)
        result = DisassembleLoadStoreMemoryTagsInstr(i, out);
    else if((op0 & ~12) == 0 && op1 == 0 && (op2 >> 1) == 0)
        result = DisassembleLoadAndStoreExclusiveInstr(i, out);
    else{
        result = 1;
    }


    /*
    unsigned int op0 = getbitsinrange(instruction->opcode, 28, 4);
    unsigned int op1 = getbitsinrange(instruction->opcode, 26, 1);
    unsigned int op2 = getbitsinrange(instruction->opcode, 23, 2);
    unsigned int op3 = getbitsinrange(instruction->opcode, 16, 6);
    unsigned int op4 = getbitsinrange(instruction->opcode, 10, 2);

    if((op0 & ~0x4) == 0 && op1 == 0x1 && (op2 == 0 || op2 == 0x1) && (op3 & ~0x1f) == 0)
        disassembled = DisassembleLoadStoreMultStructuresInstr(instruction, op2);
    else if((op0 & ~0x4) == 0 && op1 == 0x1 && (op2 == 0x2 || op2 == 0x3))
        disassembled = DisassembleLoadStoreSingleStructuresInstr(instruction, op2 == 0x2 ? 0 : 0x1);
    else if((op0 & ~0xc) == 0 && op1 == 0 && (op2 >> 1) == 0)
        disassembled = DisassembleLoadAndStoreExclusiveInstr(instruction);
    else if((op0 & ~0xc) == 0x1 && (op2 >> 0x1) == 0)
        disassembled = DisassembleLoadAndStoreLiteralInstr(instruction);
    else if((op0 & ~0xc) == 0x2 && op2 <= 0x3)
        disassembled = DisassembleLoadAndStoreRegisterPairInstr(instruction, op2);
    else if((op0 & ~0xc) == 0x3 && (op2 >> 0x1) == 0){
        if((op3 & ~0x1f) == 0)
            disassembled = DisassembleLoadAndStoreRegisterInstr(instruction, op4);
        else{
            if(op4 == 0)
                disassembled = DisassembleAtomicMemoryInstr(instruction);
            else if(op4 == 0x2)
                disassembled = DisassembleLoadAndStoreRegisterOffsetInstr(instruction);
            else if((op4 & 0x1) == 0x1)
                disassembled = DisassembleLoadAndStorePACInstr(instruction);
            else
                return strdup(".undefined");
        }
    }
    else if(((op0 & ~0xc) == 0x3 && (op2 >> 0x1) == 0x1))
        disassembled = DisassembleLoadAndStoreRegisterInstr(instruction, UNSIGNED_IMMEDIATE);
    */

    return result;
}
