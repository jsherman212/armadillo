#include <stdio.h>
#include <stdlib.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "utils.h"
#include "strext.h"

static int DisassembleCryptographicAESInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned size = bits(i->opcode, 22, 23);
    unsigned opcode = bits(i->opcode, 12, 16);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(size != 0)
        return 1;

    ADD_FIELD(out, size);
    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    struct itab tab[] = {
        { "aese", AD_INSTR_AESE }, { "aesd", AD_INSTR_AESD },
        { "aesmc", AD_INSTR_AESMC }, { "aesimc", AD_INSTR_AESIMC }
    };

    opcode -= 4;

    if(OOB(opcode, tab))
        return 1;

    const char *instr_s = tab[opcode].instr_s;
    int instr_id = tab[opcode].instr_id;

    const char **registers = AD_RTBL_FP_V_128;
    int sz = _128_BIT;

    ADD_REG_OPERAND(out, Rd, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));
    ADD_REG_OPERAND(out, Rn, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(registers));

    const char *Rd_s = GET_FP_REG(registers, Rd);
    const char *Rn_s = GET_FP_REG(registers, Rn);

    concat(&DECODE_STR(out), "%s %s.16b, %s.16b", instr_s, Rd_s, Rn_s);

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleCryptographicThreeRegisterSHAInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned size = bits(i->opcode, 22, 23);
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned opcode = bits(i->opcode, 12, 14);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(size != 0)
        return 1;

    ADD_FIELD(out, size);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    struct itab tab[] = {
        { "sha1c", AD_INSTR_SHA1C }, { "sha1p", AD_INSTR_SHA1P },
        { "sha1m", AD_INSTR_SHA1M }, { "sha1su0", AD_INSTR_SHA1SU0 },
        { "sha256h", AD_INSTR_SHA256H }, { "sha256h2", AD_INSTR_SHA256H2 },
        { "sha256su1", AD_INSTR_SHA256SU1 }
    };

    if(OOB(opcode, tab))
        return 1;

    const char *instr_s = tab[opcode].instr_s;
    int instr_id = tab[opcode].instr_id;

    concat(&DECODE_STR(out), "%s", instr_s);

    if(instr_id != AD_INSTR_SHA1SU0 && instr_id != AD_INSTR_SHA256SU1){
        const char *Rd_s = GET_FP_REG(AD_RTBL_FP_128, Rd);
        ADD_REG_OPERAND(out, Rd, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_FP_128));

        concat(&DECODE_STR(out), " %s", Rd_s);

        const char *Rn_s = NULL;

        if(instr_id == AD_INSTR_SHA256H || instr_id == AD_INSTR_SHA256H2){
            Rn_s = GET_FP_REG(AD_RTBL_FP_128, Rn);
            ADD_REG_OPERAND(out, Rn, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                    _RTBL(AD_RTBL_FP_128));

            concat(&DECODE_STR(out), ", %s", Rn_s);
        }
        else{
            Rn_s = GET_FP_REG(AD_RTBL_FP_32, Rn);
            ADD_REG_OPERAND(out, Rn, _SZ(_32_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                    _RTBL(AD_RTBL_FP_32));

            concat(&DECODE_STR(out), ", %s", Rn_s);
        }
    }
    else{
        const char *Rd_s = GET_FP_REG(AD_RTBL_FP_V_128, Rd);
        ADD_REG_OPERAND(out, Rd, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_FP_V_128));

        const char *Rn_s = GET_FP_REG(AD_RTBL_FP_V_128, Rn);
        ADD_REG_OPERAND(out, Rn, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_FP_V_128));

        concat(&DECODE_STR(out), " %s.4s, %s.4s", Rd_s, Rn_s);
    }

    const char *Rm_s = GET_FP_REG(AD_RTBL_FP_V_128, Rm);
    ADD_REG_OPERAND(out, Rm, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_FP_V_128));

    concat(&DECODE_STR(out), ", %s.4s", Rm_s);

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleCryptographicTwoRegisterSHAInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned size = bits(i->opcode, 22, 23);
    unsigned opcode = bits(i->opcode, 12, 16);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(size != 0)
        return 1;

    ADD_FIELD(out, size);
    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    struct itab tab[] = {
        { "sha1h", AD_INSTR_SHA1H }, { "sha1su1", AD_INSTR_SHA1SU1 },
        { "sha256su0", AD_INSTR_SHA256SU0 }
    };

    if(OOB(opcode, tab))
        return 1;

    const char *instr_s = tab[opcode].instr_s;
    int instr_id = tab[opcode].instr_id;

    concat(&DECODE_STR(out), "%s", instr_s);

    if(instr_id == AD_INSTR_SHA1H){
        const char *Rd_s = GET_FP_REG(AD_RTBL_FP_32, Rd);
        const char *Rn_s = GET_FP_REG(AD_RTBL_FP_32, Rn);

        ADD_REG_OPERAND(out, Rd, _SZ(_32_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_FP_32));
        ADD_REG_OPERAND(out, Rn, _SZ(_32_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_FP_32));

        concat(&DECODE_STR(out), " %s, %s", Rd_s, Rn_s);
    }
    else{
        const char *Rd_s = GET_FP_REG(AD_RTBL_FP_V_128, Rd);
        const char *Rn_s = GET_FP_REG(AD_RTBL_FP_V_128, Rn);

        ADD_REG_OPERAND(out, Rd, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_FP_V_128));
        ADD_REG_OPERAND(out, Rn, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE),
                _RTBL(AD_RTBL_FP_V_128));

        concat(&DECODE_STR(out), " %s.4s, %s.4s", Rd_s, Rn_s);
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

static int DisassembleAdvancedSIMDScalarCopyInstr(struct instruction *i,
        struct ad_insn *out){
    unsigned op = bits(i->opcode, 29, 29);
    unsigned imm5 = bits(i->opcode, 16, 20);
    unsigned imm4 = bits(i->opcode, 11, 14);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(op != 0 && imm4 != 0)
        return 1;

    ADD_FIELD(out, op);
    ADD_FIELD(out, imm5);
    ADD_FIELD(out, imm4);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    /* alias MOV is always preferred disasm for this DUP variant */
    SET_INSTR_ID(out, AD_INSTR_MOV);

    char V = '\0';
    const char **Rd_rtbl = NULL;
    unsigned Rd_sz = NONE;
    unsigned index = imm5;

    if((imm5 & ~0x1e) == 1){
        V = 'b';
        Rd_rtbl = AD_RTBL_FP_8;
        Rd_sz = _8_BIT;
        index >>= 1;
    }
    else if((imm5 & ~0x1c) == 2){
        V = 'h';
        Rd_rtbl = AD_RTBL_FP_16;
        Rd_sz = _16_BIT;
        index >>= 2;
    }
    else if((imm5 & ~0x18) == 4){
        V = 's';
        Rd_rtbl = AD_RTBL_FP_32;
        Rd_sz = _32_BIT;
        index >>= 3;
    }
    else if((imm5 & ~0x10) == 8){
        V = 'd';
        Rd_rtbl = AD_RTBL_FP_64;
        Rd_sz = _64_BIT;
        index >>= 4;
    }
    
    if(!V)
        return 1;

    const char *Rd_s = GET_FP_REG(Rd_rtbl, Rd);
    ADD_REG_OPERAND(out, Rd, Rd_sz, NO_PREFER_ZR, _SYSREG(NONE), Rd_rtbl);
    
    const char *Rn_s = GET_FP_REG(AD_RTBL_FP_V_128, Rn);
    ADD_REG_OPERAND(out, Rn, _SZ(_128_BIT), NO_PREFER_ZR, _SYSREG(NONE), _RTBL(AD_RTBL_FP_V_128));

    char T = V;

    concat(&DECODE_STR(out), "mov %s, %s.%c[%d]", Rd_s, Rn_s, T, index);

    return 0;
}

/* This function takes care of:
 *      - Advanced SIMD scalar three same FP16
 *      - Advanced SIMD scalar three same extra
 *      - Advanced SIMD scalar three same
 *      - Advanced SIMD three same (FP16)
 *      - Advanced SIMD three same extra
 *      - Advanced SIMD three same
 */
static int DisassembleAdvancedSIMDThreeSameInstr(struct instruction *i,
        struct ad_insn *out, int scalar, int fp16, int extra){
    unsigned Q = bits(i->opcode, 30, 30);
    unsigned U = bits(i->opcode, 29, 29);
    unsigned a = bits(i->opcode, 23, 23);
    unsigned size = bits(i->opcode, 22, 23);
    unsigned Rm = bits(i->opcode, 16, 20);
    
    unsigned opcode = 0;

    if(fp16)
        opcode = bits(i->opcode, 11, 13);
    else if(extra)
        opcode = bits(i->opcode, 11, 14);
    else
        opcode = bits(i->opcode, 11, 15);

    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(!scalar)
        ADD_FIELD(out, Q);

    ADD_FIELD(out, U);

    if(fp16)
        ADD_FIELD(out, a);
    else
        ADD_FIELD(out, size);

    ADD_FIELD(out, Rm);
    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    /* not a part of all instrs, don't include in field array */
    unsigned rot = bits(i->opcode, 11, 12);

    const char *instr_s = NULL;
    int instr_id = NONE;

    if(fp16){
        const char **rtbl = AD_RTBL_FP_V_128;
        unsigned sz = _128_BIT;

        if(scalar){
            rtbl = AD_RTBL_FP_16;
            sz = _16_BIT;
        }

        const char *Rd_s = GET_FP_REG(rtbl, Rd);
        const char *Rn_s = GET_FP_REG(rtbl, Rn);
        const char *Rm_s = GET_FP_REG(rtbl, Rm);

        ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

        unsigned idx = (U << 4) | (a << 3) | opcode;

        if(scalar){
            struct itab tab[] = {
                /* three blanks, idxes [0-2] */
                { NULL, NONE }, { NULL, NONE }, { NULL, NONE },
                { "fmulx", AD_INSTR_FMULX }, { "fcmeq", AD_INSTR_FCMEQ },
                /* two blanks, idxes [5-6] */
                { NULL, NONE }, { NULL, NONE },
                { "frecps", AD_INSTR_FRECPS },
                /* seven blanks, idxes [8-14] */
                { NULL, NONE }, { NULL, NONE }, { NULL, NONE },
                { NULL, NONE }, { NULL, NONE }, { NULL, NONE },
                { NULL, NONE },
                { "frsqrts", AD_INSTR_FRSQRTS },
                /* four blanks, idxes [16-19] */
                { NULL, NONE }, { NULL, NONE }, { NULL, NONE },
                { NULL, NONE },
                { "fcmge", AD_INSTR_FCMGE }, { "facge", AD_INSTR_FACGE },
                /* four blanks, idxes [22-25] */
                { NULL, NONE }, { NULL, NONE }, { NULL, NONE },
                { NULL, NONE },
                { "fabd", AD_INSTR_FABD },
                /* one blank, idx 27 */
                { NULL, NONE },
                { "fcmgt", AD_INSTR_FCMGT }, { "facgt", AD_INSTR_FACGT }
            };

            if(OOB(idx, tab))
                return 1;

            instr_s = tab[idx].instr_s;

            if(!instr_s)
                return 1;

            instr_id = tab[idx].instr_id;

            concat(&DECODE_STR(out), "%s %s, %s, %s", instr_s, Rd_s, Rn_s, Rm_s);
        }
        else{
            struct itab tab[] = {
                { "fmaxnm", AD_INSTR_FMAXNM }, { "fmla", AD_INSTR_FMLA },
                { "fadd", AD_INSTR_FADD }, { "fmulx", AD_INSTR_FMULX },
                { "fcmeq", AD_INSTR_FCMEQ },
                /* one blank, idx 5 */
                { NULL, NONE },
                { "fmax", AD_INSTR_FMAX }, { "frecps", AD_INSTR_FRECPS },
                { "fminnm", AD_INSTR_FMINNM }, { "fmls", AD_INSTR_FMLS },
                { "fsub", AD_INSTR_FSUB },
                /* three blanks, idxes [11-13] */
                { NULL, NONE }, { NULL, NONE }, { NULL, NONE },
                { "fmin", AD_INSTR_FMIN }, { "frsqrts", AD_INSTR_FRSQRTS },
                { "fmaxnmp", AD_INSTR_FMAXNMP },
                /* one blank, idx 17 */
                { NULL, NONE },
                { "faddp", AD_INSTR_FADDP }, { "fmul", AD_INSTR_FMUL },
                { "fcmge", AD_INSTR_FCMGE }, { "facge", AD_INSTR_FACGE },
                { "fmaxp", AD_INSTR_FMAXP }, { "fdiv", AD_INSTR_FDIV },
                { "fminnmp", AD_INSTR_FMINNMP },
                /* one blank, idx 25 */
                { NULL, NONE },
                { "fabd", AD_INSTR_FABD },
                /* one blank, idx 27 */
                { NULL, NONE },
                { "fcmgt", AD_INSTR_FCMGT }, { "fminp", AD_INSTR_FMINP }
            };

            if(OOB(idx, tab))
                return 1;

            instr_s = tab[idx].instr_s;

            if(!instr_s)
                return 1;

            instr_id = tab[idx].instr_id;

            const char *arrangement = Q == 0 ? "4h" : "8h";

            concat(&DECODE_STR(out), "%s %s.%s, %s.%s, %s.%s", instr_s, Rd_s,
                    arrangement, Rn_s, arrangement, Rm_s, arrangement);
        }
    }
    else if(extra){
        if(scalar){
            if(U != 1)
                return 1;

            if(size == 0 || size == 3)
                return 1;

            instr_s = opcode == 0 ? "sqrdmlah" : "sqrdmlsh";
            instr_id = opcode == 0 ? AD_INSTR_SQRDMLAH : AD_INSTR_SQRDMLSH;

            const char **rtbl = AD_RTBL_FP_16;
            unsigned sz = _16_BIT;

            if(size == 2){
                rtbl = AD_RTBL_FP_32;
                sz = _32_BIT;
            }

            const char *Rd_s = GET_FP_REG(rtbl, Rd);
            const char *Rn_s = GET_FP_REG(rtbl, Rn);
            const char *Rm_s = GET_FP_REG(rtbl, Rm);

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
            ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

            concat(&DECODE_STR(out), "%s %s, %s, %s", instr_s, Rd_s, Rn_s, Rm_s);
        }
        else{
            const char **rtbl = AD_RTBL_FP_V_128;
            unsigned sz = _128_BIT;

            const char *Rd_s = GET_FP_REG(rtbl, Rd);
            const char *Rn_s = GET_FP_REG(rtbl, Rn);
            const char *Rm_s = GET_FP_REG(rtbl, Rm);

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
            ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

            if(opcode == 2){
                instr_s = U == 0 ? "sdot" : "udot";
                instr_id = U == 0 ? AD_INSTR_SDOT : AD_INSTR_UDOT;

                const char *Ta = Q == 0 ? "2s" : "4s";
                const char *Tb = Q == 0 ? "8b" : "16b";

                concat(&DECODE_STR(out), "%s %s.%s, %s.%s, %s.%s", instr_s,
                        Rd_s, Ta, Rn_s, Tb, Rm_s, Tb);
            }
            else{
                if(opcode < 2){
                    instr_s = opcode == 0 ? "sqrdmlah" : "sqrdmlsh";
                    instr_id = opcode == 0 ? AD_INSTR_SQRDMLAH : AD_INSTR_SQRDMLSH;
                }
                else{
                    if((opcode & ~3) == 8){
                        instr_s = "fcmla";
                        instr_id = AD_INSTR_FCMLA;
                    }
                    else if((opcode & ~2) == 12){
                        instr_s = "fcadd";
                        instr_id = AD_INSTR_FCADD;
                    }
                    else{
                        return 1;
                    }
                }

                const char *arrangement = NULL;

                if(size == 1)
                    arrangement = Q == 0 ? "4h" : "8h";
                else if(size == 2)
                    arrangement = Q == 0 ? "2s" : "4s";
                else if((instr_id == AD_INSTR_FCMLA || instr_id == AD_INSTR_FCADD) &&
                        size == 3 && Q == 1){
                    arrangement = "2d";
                }

                if(!arrangement)
                    return 1;

                concat(&DECODE_STR(out), "%s %s.%s, %s.%s, %s.%s", instr_s,
                        Rd_s, arrangement, Rn_s, arrangement, Rm_s, arrangement);

                if(instr_id == AD_INSTR_FCMLA || instr_id == AD_INSTR_FCADD){
                    unsigned rotate = 0;

                    if(instr_id == AD_INSTR_FCMLA)
                        rotate = rot * 90;
                    else
                        rotate = rot == 0 ? 90 : 270;

                    concat(&DECODE_STR(out), ", #%d", rotate);

                    if(rotate > 0)
                        ADD_IMM_OPERAND(out, AD_UINT, *(unsigned *)&rotate);
                }
            }
        }
    }
    else{
        const char **rtbls[] = {
            AD_RTBL_FP_8, AD_RTBL_FP_16, AD_RTBL_FP_32, AD_RTBL_FP_64
        };
        
        unsigned sizes[] = {
            _8_BIT, _16_BIT, _32_BIT, _64_BIT
        };

        const char **rtbl = NULL;
        const char *T = NULL;

        unsigned sz = 0;
        
        if(opcode == 0){
            if(scalar)
                return 1;

            instr_s = "shadd";
            instr_id = AD_INSTR_SHADD;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 1){
            instr_s = U == 0 ? "sqadd" : "uqadd";
            instr_id = U == 0 ? AD_INSTR_SQADD : AD_INSTR_UQADD;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;
            
            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 2){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "srhadd" : "urhadd";
            instr_id = U == 0 ? AD_INSTR_SRHADD : AD_INSTR_URHADD;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 3){
            if(scalar)
                return 1;

            struct itab u0[] = {
                { "and", AD_INSTR_AND }, { "bic", AD_INSTR_BIC },
                { "orr", AD_INSTR_ORR }, { "orn", AD_INSTR_ORN }
            };

            struct itab u1[] = {
                { "eor", AD_INSTR_EOR }, { "bsl", AD_INSTR_BSL },
                { "bit", AD_INSTR_BIT }, { "bif", AD_INSTR_BIF }
            };

            /* both table sizes are the same, don't need to check u1 */
            if(OOB(size, u0))
                return 1;

            instr_s = U == 0 ? u0[size].instr_s : u1[size].instr_s;
            instr_id = U == 0 ? u0[size].instr_id : u1[size].instr_id;

            T = Q == 0 ? "8b" : "16b";

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 4){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "shsub" : "uhsub";
            instr_id = U == 0 ? AD_INSTR_SHSUB : AD_INSTR_UHSUB;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 5){
            instr_s = U == 0 ? "sqsub" : "uqsub";
            instr_id = U == 0 ? AD_INSTR_SQSUB : AD_INSTR_UQSUB;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 6){
            if(scalar && size != 3)
                return 1;

            instr_s = U == 0 ? "cmgt" : "cmhi";
            instr_id = U == 0 ? AD_INSTR_CMGT : AD_INSTR_CMHI;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 7){
            if(scalar && size != 3)
                return 1;

            instr_s = U == 0 ? "cmge" : "cmhs";
            instr_id = U == 0 ? AD_INSTR_CMGE : AD_INSTR_CMHS;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 8){
            if(scalar && size != 3)
                return 1;

            instr_s = U == 0 ? "sshl" : "ushl";
            instr_id = U == 0 ? AD_INSTR_SSHL : AD_INSTR_USHL;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 9){
            instr_s = U == 0 ? "sqshl" : "uqshl";
            instr_id = U == 0 ? AD_INSTR_SQSHL : AD_INSTR_UQSHL;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0xa){
            if(scalar && size != 3)
                return 1;

            instr_s = U == 0 ? "srshl" : "urshl";
            instr_id = U == 0 ? AD_INSTR_SRSHL : AD_INSTR_URSHL;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0xb){
            instr_s = U == 0 ? "sqrshl" : "uqrshl";
            instr_id = U == 0 ? AD_INSTR_SQRSHL : AD_INSTR_UQRSHL;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0xc){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "smax" : "umax";
            instr_id = U == 0 ? AD_INSTR_SMAX : AD_INSTR_UMAX;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0xd){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "smin" : "umin";
            instr_id = U == 0 ? AD_INSTR_SMIN : AD_INSTR_UMIN;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0xe){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "sabd" : "uabd";
            instr_id = U == 0 ? AD_INSTR_SABD : AD_INSTR_UABD;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0xf){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "saba" : "uaba";
            instr_id = U == 0 ? AD_INSTR_SABA : AD_INSTR_UABA;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x10){
            if(scalar && size != 3)
                return 1;

            instr_s = U == 0 ? "add" : "sub";
            instr_id = U == 0 ? AD_INSTR_ADD : AD_INSTR_SUB;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0x11){
            if(scalar && size != 3)
                return 1;

            instr_s = U == 0 ? "cmtst" : "cmeq";
            instr_id = U == 0 ? AD_INSTR_CMTST : AD_INSTR_CMEQ;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0x12){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "mla" : "mls";
            instr_id = U == 0 ? AD_INSTR_MLA : AD_INSTR_MLS;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x13){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "mul" : "pmul";
            instr_id = U == 0 ? AD_INSTR_MUL : AD_INSTR_PMUL;

            if(instr_id == AD_INSTR_PMUL)
                T = Q == 0 ? "8b" : "16b";
            else{
                if(size == 0)
                    T = Q == 0 ? "8b" : "16b";
                else if(size == 1)
                    T = Q == 0 ? "4h" : "8h";
                else if(size == 2)
                    T = Q == 0 ? "2s" : "4s";
            }

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x14){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "smaxp" : "umaxp";
            instr_id = U == 0 ? AD_INSTR_SMAXP : AD_INSTR_UMAXP;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x15){
            if(scalar)
                return 1;

            instr_s = U == 0 ? "sminp" : "uminp";
            instr_id = U == 0 ? AD_INSTR_SMINP : AD_INSTR_UMINP;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x16){
            if(scalar && (size == 0 || size == 3))
                return 1;

            instr_s = U == 0 ? "sqdmulh" : "sqrdmulh";
            instr_id = U == 0 ? AD_INSTR_SQDMULH : AD_INSTR_SQRDMULH;

            if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";

            if(!scalar && !T)
                return 1;

            if(scalar){
                rtbl = rtbls[size];
                sz = sizes[size];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0x17){
            if(scalar)
                return 1;

            if(U == 1)
                return 1;

            instr_s = "addp";
            instr_id = AD_INSTR_ADDP;

            if(size == 0)
                T = Q == 0 ? "8b" : "16b";
            else if(size == 1)
                T = Q == 0 ? "4h" : "8h";
            else if(size == 2)
                T = Q == 0 ? "2s" : "4s";
            else if(size == 3 && Q == 1)
                T = "2d";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x18){
            if(scalar)
                return 1;

            unsigned s = size >> 1;

            if(U == 0){
                instr_s = s == 0 ? "fmaxnm" : "fminnm";
                instr_id = s == 0 ? AD_INSTR_FMAXNM : AD_INSTR_FMINNM;
            }
            else{
                instr_s = s == 0 ? "fmaxnmp" : "fminnmp";
                instr_id = s == 0 ? AD_INSTR_FMAXNMP : AD_INSTR_FMINNMP;
            }

            unsigned _sz = (size & 1);

            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x19){
            if(scalar)
                return 1;

            unsigned s = size >> 1;

            if(U == 0){
                instr_s = s == 0 ? "fmla" : "fmls";
                instr_id = s == 0 ? AD_INSTR_FMLA : AD_INSTR_FMLS;
            }
            else{
                if(size == 1 || size == 3)
                    return 1;

                instr_s = size == 0 ? "fmlal2" : "fmlsl2";
                instr_id = size == 0 ? AD_INSTR_FMLAL2 : AD_INSTR_FMLSL2;

                const char *Ta = Q == 0 ? "2s" : "4s";
                const char *Tb = Q == 0 ? "2h" : "4h";

                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;

                const char *Rd_s = GET_FP_REG(rtbl, Rd);
                const char *Rn_s = GET_FP_REG(rtbl, Rn);
                const char *Rm_s = GET_FP_REG(rtbl, Rm);

                ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
                ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
                ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

                concat(&DECODE_STR(out), "%s %s.%s, %s.%s, %s.%s", instr_s, Rd_s,
                        Ta, Rn_s, Tb, Rm_s, Tb);

                SET_INSTR_ID(out, instr_id);

                return 0;
            }

            unsigned _sz = (size & 1);

            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x1a){
            unsigned s = size >> 1;
            unsigned _sz = (size & 1);

            if(scalar){
                if(U != 1 && s != 1)
                    return 1;

                instr_s = "fabd";
                instr_id = AD_INSTR_FABD;

                rtbl = rtbls[2 + _sz];
                sz = sizes[2 + _sz];
            }
            else{
                if(U == 0){
                    instr_s = s == 0 ? "fadd" : "fsub";
                    instr_id = s == 0 ? AD_INSTR_FADD : AD_INSTR_FSUB;
                }
                else{
                    instr_s = s == 0 ? "faddp" : "fabd";
                    instr_id = s == 0 ? AD_INSTR_FADDP : AD_INSTR_FABD;
                }

                if(_sz == 0)
                    T = Q == 0 ? "2s" : "4s";
                else if(_sz == 1 && Q == 1)
                    T = "2d";

                if(!T)
                    return 1;

                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0x1b){
            unsigned s = size >> 1;
            unsigned _sz = (size & 1);

            if(scalar){
                if(s == 1)
                    return 1;

                if(U == 1 && s == 0)
                    return 1;

                instr_s = "fmulx";
                instr_id = AD_INSTR_FMULX;

                rtbl = rtbls[2 + _sz];
                sz = sizes[2 + _sz];
            }
            else{
                if(s == 1)
                    return 1;

                instr_s = U == 0 ? "fmulx" : "fmul";
                instr_id = U == 0 ? AD_INSTR_FMULX : AD_INSTR_FMUL;

                if(_sz == 0)
                    T = Q == 0 ? "2s" : "4s";
                else if(_sz == 1 && Q == 1)
                    T = "2d";

                if(!T)
                    return 1;

                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }
        }
        else if(opcode == 0x1c){
            unsigned s = size >> 1;
            unsigned _sz = (size & 1);

            if(U == 0 && s == 1)
                return 1;

            if(U == 0){
                instr_s = "fcmeq";
                instr_id = AD_INSTR_FCMEQ;
            }
            else{
                instr_s = s == 0 ? "fcmge" : "fcmgt";
                instr_id = s == 0 ? AD_INSTR_FCMGE : AD_INSTR_FCMGT;
            }

            if(scalar){
                rtbl = rtbls[2 + _sz];
                sz = sizes[2 + _sz];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }

            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;
        }
        else if(opcode == 0x1d){
            unsigned s = size >> 1;
            unsigned _sz = (size & 1);

            if(scalar && U == 0)
                return 1;

            if(U == 1){
                instr_s = s == 0 ? "facge" : "facgt";
                instr_id = s == 0 ? AD_INSTR_FACGE : AD_INSTR_FACGT;
            }
            else{
                if(size == 1 || size == 3)
                    return 1;

                instr_s = size == 0 ? "fmlal" : "fmlsl";
                instr_id = size == 0 ? AD_INSTR_FMLAL : AD_INSTR_FMLSL;

                const char *Ta = Q == 0 ? "2s" : "4s";
                const char *Tb = Q == 0 ? "2h" : "4h";

                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;

                const char *Rd_s = GET_FP_REG(rtbl, Rd);
                const char *Rn_s = GET_FP_REG(rtbl, Rn);
                const char *Rm_s = GET_FP_REG(rtbl, Rm);

                ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
                ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
                ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

                concat(&DECODE_STR(out), "%s %s.%s, %s.%s, %s.%s", instr_s, Rd_s,
                        Ta, Rn_s, Tb, Rm_s, Tb);

                SET_INSTR_ID(out, instr_id);

                return 0;
            }
            
            if(scalar){
                rtbl = rtbls[2 + _sz];
                sz = sizes[2 + _sz];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }

            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!scalar && !T)
                return 1;
        }
        else if(opcode == 0x1e){
            if(scalar)
                return 1;

            unsigned s = size >> 1;
            unsigned _sz = (size & 1);

            if(U == 0){
                instr_s = s == 0 ? "fmax" : "fmin";
                instr_id = s == 0 ? AD_INSTR_FMAX : AD_INSTR_FMIN;
            }
            else{
                instr_s = s == 0 ? "fmaxp" : "fminp";
                instr_id = s == 0 ? AD_INSTR_FMAXP : AD_INSTR_FMINP;
            }

            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else if(opcode == 0x1f){
            unsigned s = size >> 1;
            unsigned _sz = (size & 1);

            if(scalar && U != 0)
                return 1;

            if(U == 0){
                instr_s = s == 0 ? "frecps" : "frsqrts";
                instr_id = s == 0 ? AD_INSTR_FRECPS : AD_INSTR_FRSQRTS;
            }
            else{
                if(s == 1)
                    return 1;

                instr_s = "fdiv";
                instr_id = AD_INSTR_FDIV;
            }

            if(scalar){
                rtbl = rtbls[2 + _sz];
                sz = sizes[2 + _sz];
            }
            else{
                rtbl = AD_RTBL_FP_V_128;
                sz = _128_BIT;
            }

            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;
        }

        if(!rtbl)
            return 1;

        const char *Rd_s = GET_FP_REG(rtbl, Rd);
        const char *Rn_s = GET_FP_REG(rtbl, Rn);
        const char *Rm_s = GET_FP_REG(rtbl, Rm);

        ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

        concat(&DECODE_STR(out), "%s %s", instr_s, Rd_s);

        if(scalar)
            concat(&DECODE_STR(out), ", %s, %s", Rn_s, Rm_s);
        else
            concat(&DECODE_STR(out), ".%s, %s.%s, %s.%s", T, Rn_s, T, Rm_s, T);
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

/* This function takes care of:
 *      - Advanced SIMD scalar two-register miscellaneous FP16
 *      - Advanced SIMD scalar two-register miscellaneous
 *      - Advanced SIMD two-register miscellaneous (FP16)
 *      - Advanced SIMD two-register miscellaneous
 */
static int DisassembleAdvancedSIMDTwoRegisterMiscellaneousInstr(struct instruction *i,
        struct ad_insn *out, int scalar, int fp16){
    unsigned Q = bits(i->opcode, 30, 30);
    unsigned U = bits(i->opcode, 29, 29);
    unsigned a = bits(i->opcode, 23, 23);
    unsigned size = bits(i->opcode, 22, 23);
    unsigned opcode = bits(i->opcode, 12, 16);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned Rd = bits(i->opcode, 0, 4);

    if(!scalar)
        ADD_FIELD(out, Q);

    ADD_FIELD(out, U);

    if(fp16)
        ADD_FIELD(out, a);
    else
        ADD_FIELD(out, size);

    ADD_FIELD(out, opcode);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Rd);

    const char *instr_s = NULL;
    int instr_id = NONE;

    const char **rtbls[] = {
        AD_RTBL_FP_8, AD_RTBL_FP_16, AD_RTBL_FP_32, AD_RTBL_FP_64
    };

    unsigned sizes[] = {
        _8_BIT, _16_BIT, _32_BIT, _64_BIT
    };

    const char **rtbl = NULL;
    const char *T = NULL;

    unsigned sz = 0;

    int add_zero = 0;
    int add_zerof = 0;

    if(opcode < 2){
        if(scalar || fp16)
            return 1;

        if(opcode == 1 && U == 1)
            return 1;

        unsigned o0 = bits(i->opcode, 12, 12);
        unsigned op = (o0 << 1) | U;

        struct itab tab[] = {
            { "rev64", AD_INSTR_REV64 }, { "rev32", AD_INSTR_REV32 },
            { "rev16", AD_INSTR_REV16 }
        };

        if(OOB(op, tab))
            return 1;

        instr_s = tab[op].instr_s;
        instr_id = tab[op].instr_id;

        if(size == 0)
            T = Q == 0 ? "8b" : "16b";
        else if(size == 1)
            T = Q == 0 ? "4h" : "8h";
        else if(size == 2)
            T = Q == 0 ? "2s" : "4s";

        if(!T)
            return 1;

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;
    }
    else if(opcode == 2 || opcode == 6){
        if(scalar || fp16)
            return 1;

        if(opcode == 2){
            instr_s = U == 0 ? "saddlp" : "uaddlp";
            instr_id = U == 0 ? AD_INSTR_SADDLP : AD_INSTR_UADDLP;
        }
        else{
            instr_s = U == 0 ? "sadalp" : "uadalp";
            instr_id = U == 0 ? AD_INSTR_SADALP : AD_INSTR_UADALP;
        }

        const char *Ta = NULL;
        const char *Tb = NULL;

        if(size == 0){
            Ta = Q == 0 ? "4h" : "8h";
            Tb = Q == 0 ? "8b" : "16b";
        }
        else if(size == 1){
            Ta = Q == 0 ? "2s" : "4s";
            Tb = Q == 0 ? "4h" : "8h";
        }
        else if(size == 2){
            Ta = Q == 0 ? "1d" : "2d";
            Tb = Q == 0 ? "2s" : "4s";
        }

        if(!Ta || !Tb)
            return 1;

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;

        const char *Rd_s = GET_FP_REG(rtbl, Rd);
        const char *Rn_s = GET_FP_REG(rtbl, Rn);

        ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

        concat(&DECODE_STR(out), "%s %s.%s, %s.%s", instr_s, Rd_s, Ta, Rn_s, Tb);

        SET_INSTR_ID(out, instr_id);

        return 0;
    }
    else if(opcode == 3 || opcode == 7){
        if(fp16)
            return 1;

        if(opcode == 3){
            instr_s = U == 0 ? "suqadd" : "usqadd";
            instr_id = U == 0 ? AD_INSTR_SUQADD : AD_INSTR_USQADD;
        }
        else{
            instr_s = U == 0 ? "sqabs" : "sqneg";
            instr_id = U == 0 ? AD_INSTR_SQABS : AD_INSTR_SQNEG;
        }

        if(size == 0)
            T = Q == 0 ? "8b" : "16b";
        else if(size == 1)
            T = Q == 0 ? "4h" : "8h";
        else if(size == 2)
            T = Q == 0 ? "2s" : "4s";
        else if(size == 3 && Q == 1)
            T = "2d";

        if(!scalar && !T)
            return 1;

        if(scalar){
            rtbl = rtbls[size];
            sz = sizes[size];
        }
        else{
            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
    }
    else if(opcode == 4){
        if(scalar || fp16)
            return 1;

        instr_s = U == 0 ? "cls" : "clz";
        instr_id = U == 0 ? AD_INSTR_CLS : AD_INSTR_CLZ;

        if(size == 0)
            T = Q == 0 ? "8b" : "16b";
        else if(size == 1)
            T = Q == 0 ? "4h" : "8h";
        else if(size == 2)
            T = Q == 0 ? "2s" : "4s";
        else if(size == 3 && Q == 1)
            T = "2d";

        if(!T)
            return 1;

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;
    }
    else if(opcode == 5){
        if(scalar || fp16)
            return 1;

        if(U == 0){
            if(size != 0)
                return 1;

            instr_s = "cnt";
            instr_id = AD_INSTR_CNT;
        }
        else{
            if((size >> 1) == 1)
                return 1;
            
            instr_s = size == 0 ? "not" : "rbit";
            instr_id = size == 0 ? AD_INSTR_NOT : AD_INSTR_RBIT;
        }

        T = Q == 0 ? "8b" : "16b";

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;
    }
    else if(opcode >= 8 && opcode <= 0xa){
        if(fp16)
            return 1;

        if(opcode == 0xa && U == 1)
            return 1;

        if(scalar && size != 3)
            return 1;

        unsigned op = bits(i->opcode, 12, 12);
        unsigned cop = (op << 1) | U;

        struct itab tab[] = {
            { "cmgt", AD_INSTR_CMGT }, { "cmge", AD_INSTR_CMGE },
            { "cmeq", AD_INSTR_CMEQ }, { "cmle", AD_INSTR_CMLE }
        };

        instr_s = tab[cop].instr_s;
        instr_id = tab[cop].instr_id;

        if(size == 0)
            T = Q == 0 ? "8b" : "16b";
        else if(size == 1)
            T = Q == 0 ? "4h" : "8h";
        else if(size == 2)
            T = Q == 0 ? "2s" : "4s";
        else if(size == 3 && Q == 1)
            T = "2d";

        if(!scalar && !T)
            return 1;

        if(scalar){
            rtbl = rtbls[size];
            sz = sizes[size];
        }
        else{
            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }

        add_zero = 1;
    }
    else if(opcode == 0xb){
        if(fp16)
            return 1;

        if(scalar && size != 3)
            return 1;

        instr_s = U == 0 ? "abs" : "neg";
        instr_id = U == 0 ? AD_INSTR_ABS : AD_INSTR_NEG;

        if(size == 0)
            T = Q == 0 ? "8b" : "16b";
        else if(size == 1)
            T = Q == 0 ? "4h" : "8h";
        else if(size == 2)
            T = Q == 0 ? "2s" : "4s";
        else if(size == 3 && Q == 1)
            T = "2d";

        if(!scalar && !T)
            return 1;

        if(scalar){
            rtbl = rtbls[size];
            sz = sizes[size];
        }
        else{
            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
    }
    else if(opcode >= 0xc && opcode <= 0xe){
        if(opcode == 0xe && U == 1)
            return 1;

        unsigned _sz = (size & 1);

        unsigned op = bits(i->opcode, 12, 12);
        unsigned cop = (op << 1) | U;

        struct itab tab[] = {
            { "fcmgt", AD_INSTR_FCMGT }, { "fcmge", AD_INSTR_FCMGE },
            { "fcmeq", AD_INSTR_FCMEQ }, { "fcmle", AD_INSTR_FCMLE }
        };

        instr_s = tab[cop].instr_s;
        instr_id = tab[cop].instr_id;

        if(scalar && fp16){
            T = Q == 0 ? "4h" : "8h";

            rtbl = AD_RTBL_FP_16;
            sz = _16_BIT;
        }
        else if(scalar){
            rtbl = rtbls[2 + _sz];
            sz = sizes[2 + _sz];
        }
        else if(fp16){
            T = Q == 0 ? "4h" : "8h";

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else{
            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }

        add_zerof = 1;
    }
    else if(opcode == 0xf){
        if(scalar)
            return 1;

        instr_s = U == 0 ? "fabs" : "fneg";
        instr_id = U == 0 ? AD_INSTR_FABS : AD_INSTR_FNEG;

        unsigned _sz = (size & 1);

        if(fp16)
            T = Q == 0 ? "4h" : "8h";
        else{
            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;
        }

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;
    }
    else if(opcode == 0x12 || opcode == 0x14){
        if(fp16)
            return 1;

        if(scalar && size == 3)
            return 1;

        if(U == 0){
            if(opcode == 0x12){
                instr_s = Q == 0 ? "xtn" : "xtn2";
                instr_id = Q == 0 ? AD_INSTR_XTN : AD_INSTR_XTN2;
            }
            else{
                if(scalar){
                    instr_s = "sqxtn";
                    instr_id = AD_INSTR_SQXTN;
                }
                else{
                    instr_s = Q == 0 ? "sqxtn" : "sqxtn2";
                    instr_id = Q == 0 ? AD_INSTR_SQXTN : AD_INSTR_SQXTN2;
                }
            }
        }
        else{
            if(opcode == 0x12){
                if(scalar){
                    instr_s = "sqxtun";
                    instr_id = AD_INSTR_SQXTUN;
                }
                else{
                    instr_s = Q == 0 ? "sqxtun" : "sqxtun2";
                    instr_id = Q == 0 ? AD_INSTR_SQXTUN : AD_INSTR_SQXTUN2;
                }
            }
            else{
                if(scalar){
                    instr_s = "uqxtn";
                    instr_id = AD_INSTR_UQXTN;
                }
                else{
                    instr_s = Q == 0 ? "uqxtn" : "uqxtn2";
                    instr_id = Q == 0 ? AD_INSTR_UQXTN : AD_INSTR_UQXTN2;
                }
            }
        }

        concat(&DECODE_STR(out), "%s", instr_s);

        if(scalar){
            const char **Rd_rtbl = rtbls[size];
            const char **Rn_rtbl = rtbls[1 + size];

            unsigned Rd_sz = sizes[size];
            unsigned Rn_sz = sizes[1 + size];

            const char *Rd_s = GET_FP_REG(Rd_rtbl, Rd);
            const char *Rn_s = GET_FP_REG(Rn_rtbl, Rn);

            ADD_REG_OPERAND(out, Rd, Rd_sz, NO_PREFER_ZR, _SYSREG(NONE), Rd_rtbl);
            ADD_REG_OPERAND(out, Rn, Rn_sz, NO_PREFER_ZR, _SYSREG(NONE), Rn_rtbl);

            concat(&DECODE_STR(out), " %s, %s", Rd_s, Rn_s);
        }
        else{
            const char *Ta = NULL;
            const char *Tb = NULL;

            if(size == 0){
                Ta = "8h";
                Tb = Q == 0 ? "8b" : "16b";
            }
            else if(size == 1){
                Ta = "4s";
                Tb = Q == 0 ? "4h" : "8h";
            }
            else if(size == 2){
                Ta = "2d";
                Tb = Q == 0 ? "2s" : "4s";
            }

            if(!Ta || !Tb)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;

            const char *Rd_s = GET_FP_REG(rtbl, Rd);
            const char *Rn_s = GET_FP_REG(rtbl, Rn);

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

            concat(&DECODE_STR(out), " %s.%s, %s.%s", Rd_s, Tb, Rn_s, Ta);
        }

        SET_INSTR_ID(out, instr_id);

        return 0;
    }
    else if(opcode == 0x13){
        if(fp16 || scalar)
            return 1;

        if(U == 0)
            return 1;

        instr_s = Q == 0 ? "shll" : "shll2";
        instr_id = Q == 0 ? AD_INSTR_SHLL : AD_INSTR_SHLL2;

        const char *Ta = NULL;
        const char *Tb = NULL;

        if(size == 0){
            Ta = "8h";
            Tb = Q == 0 ? "8b" : "16b";
        }
        else if(size == 1){
            Ta = "4s";
            Tb = Q == 0 ? "4h" : "8h";
        }
        else if(size == 2){
            Ta = "2d";
            Tb = Q == 0 ? "2s" : "4s";
        }

        if(!Ta || !Tb)
            return 1;

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;

        const char *Rd_s = GET_FP_REG(rtbl, Rd);
        const char *Rn_s = GET_FP_REG(rtbl, Rn);

        ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

        unsigned shift = 8 << size;

        ADD_IMM_OPERAND(out, AD_UINT, *(unsigned *)&shift);

        concat(&DECODE_STR(out), "%s %s.%s, %s.%s, #%#x", instr_s, Rd_s, Ta,
                Rn_s, Tb, shift);

        SET_INSTR_ID(out, instr_id);

        return 0;
    }
    else if(opcode == 0x16){
        if(fp16)
            return 1;

        unsigned _sz = (size & 1);

        if(U == 0){
            instr_s = Q == 0 ? "fcvtn" : "fcvtn2";
            instr_id = Q == 0 ? AD_INSTR_FCVTN : AD_INSTR_FCVTN2;
        }
        else{
            if(scalar){
                instr_s = "fcvtxn";
                instr_id = AD_INSTR_FCVTXN;
            }
            else{
                instr_s = Q == 0 ? "fcvtxn" : "fcvtxn2";
                instr_id = Q == 0 ? AD_INSTR_FCVTXN : AD_INSTR_FCVTXN2;
            }
        }

        concat(&DECODE_STR(out), "%s", instr_s);

        if(scalar){
            if(_sz == 0)
                return 1;

            const char **Rd_rtbl = AD_RTBL_FP_32;
            const char **Rn_rtbl = AD_RTBL_FP_64;

            unsigned Rd_sz = _32_BIT;
            unsigned Rn_sz = _64_BIT;

            const char *Rd_s = GET_FP_REG(Rd_rtbl, Rd);
            const char *Rn_s = GET_FP_REG(Rn_rtbl, Rn);

            ADD_REG_OPERAND(out, Rd, Rd_sz, NO_PREFER_ZR, _SYSREG(NONE), Rd_rtbl);
            ADD_REG_OPERAND(out, Rn, Rn_sz, NO_PREFER_ZR, _SYSREG(NONE), Rn_rtbl);

            concat(&DECODE_STR(out), " %s, %s", Rd_s, Rn_s);
        }
        else{
            const char *Ta = NULL;
            const char *Tb = NULL;

            if(_sz == 0){
                if(instr_id == AD_INSTR_FCVTXN || instr_id == AD_INSTR_FCVTXN2)
                    return 1;

                Ta = "4s";
                Tb = Q == 0 ? "4h" : "8h";
            }
            else if(_sz == 1){
                Ta = "2d";
                Tb = Q == 0 ? "2s" : "4s";
            }

            if(!Ta || !Tb)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;

            const char *Rd_s = GET_FP_REG(rtbl, Rd);
            const char *Rn_s = GET_FP_REG(rtbl, Rn);

            ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
            ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

            concat(&DECODE_STR(out), " %s.%s, %s.%s", Rd_s, Tb, Rn_s, Ta);
        }

        SET_INSTR_ID(out, instr_id);

        return 0;
    }
    else if(opcode == 0x17){
        if(fp16 || scalar)
            return 1;

        unsigned _sz = (size & 1);

        instr_s = Q == 0 ? "fcvtl" : "fcvtl2";
        instr_id = Q == 0 ? AD_INSTR_FCVTL : AD_INSTR_FCVTL2;

        const char *Ta = NULL;
        const char *Tb = NULL;

        if(_sz == 0){
            Ta = "4s";
            Tb = Q == 0 ? "4h" : "8h";
        }
        else if(_sz == 1){
            Ta = "2d";
            Tb = Q == 0 ? "2s" : "4s";
        }

        if(!Ta || !Tb)
            return 1;

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;

        const char *Rd_s = GET_FP_REG(rtbl, Rd);
        const char *Rn_s = GET_FP_REG(rtbl, Rn);

        ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

        concat(&DECODE_STR(out), "%s %s.%s, %s.%s", instr_s, Rd_s, Ta, Rn_s, Tb);

        SET_INSTR_ID(out, instr_id);

        return 0;
    }
    else if(opcode == 0x18 || opcode == 0x19 || opcode == 0x1e || opcode == 0x1f){
        if(scalar)
            return 1;

        unsigned s = size >> 1;
        unsigned _sz = (size & 1);

        if(U == 0){
            if(s == 0){
                if(opcode == 0x18){
                    instr_s = "frintn";
                    instr_id = AD_INSTR_FRINTN;
                }
                else if(opcode == 0x19){
                    instr_s = "frintm";
                    instr_id = AD_INSTR_FRINTM;
                }
                else if(opcode == 0x1e){
                    instr_s = "frint32z";
                    instr_id = AD_INSTR_FRINT32Z;
                }
                else{
                    instr_s = "frint64z";
                    instr_id = AD_INSTR_FRINT64Z;
                }
            }
            else{
                if(opcode == 0x1e || opcode == 0x1f)
                    return 1;

                instr_s = opcode == 0x18 ? "frintp" : "frintz";
                instr_id = opcode == 0x18 ? AD_INSTR_FRINTP : AD_INSTR_FRINTZ;
            }
        }
        else{
            if(s == 0){
                if(opcode == 0x18){
                    instr_s = "frinta";
                    instr_id = AD_INSTR_FRINTA;
                }
                else if(opcode == 0x19){
                    instr_s = "frintx";
                    instr_id = AD_INSTR_FRINTX;
                }
                else if(opcode == 0x1e){
                    instr_s = "frint32x";
                    instr_id = AD_INSTR_FRINT32X;
                }
                else{
                    instr_s = "frint64x";
                    instr_id = AD_INSTR_FRINT64X;
                }
            }
            else{
                if(opcode == 0x18 || opcode == 0x1e)
                    return 1;

                instr_s = opcode == 0x19 ? "frinti" : "fsqrt";
                instr_id = opcode == 0x19 ? AD_INSTR_FRINTI : AD_INSTR_FSQRT;
            }
        }

        if(fp16)
            T = Q == 0 ? "4h" : "8h";
        else{
            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1)
                T = "2d";

            if(!T)
                return 1;
        }

        rtbl = AD_RTBL_FP_V_128;
        sz = _128_BIT;
    }
    else if(opcode >= 0x1a && opcode <= 0x1d){
        unsigned s = size >> 1;
        unsigned tempop = opcode - 0x1a;

        if(U == 0){
            if(s == 0){
                struct itab tab[] = {
                    { "fcvtns", AD_INSTR_FCVTNS }, { "fcvtms", AD_INSTR_FCVTMS },
                    { "fcvtas", AD_INSTR_FCVTAS }, { "scvtf", AD_INSTR_SCVTF }
                };

                if(OOB(tempop, tab))
                    return 1;

                instr_s = tab[tempop].instr_s;
                instr_id = tab[tempop].instr_id;
            }
            else{
                struct itab tab[] = {
                    { "fcvtps", AD_INSTR_FCVTPS }, { "fcvtzs", AD_INSTR_FCVTZS },
                    { "urecpe", AD_INSTR_URECPE }, { "frecpe", AD_INSTR_FRECPE }
                };

                if(OOB(tempop, tab))
                    return 1;

                instr_s = tab[tempop].instr_s;
                instr_id = tab[tempop].instr_id;
            }
        }
        else{
            if(s == 0){
                struct itab tab[] = {
                    { "fcvtnu", AD_INSTR_FCVTNU }, { "fcvtmu", AD_INSTR_FCVTMU },
                    { "fcvtau", AD_INSTR_FCVTAU }, { "ucvtf", AD_INSTR_UCVTF }
                };

                if(OOB(tempop, tab))
                    return 1;

                instr_s = tab[tempop].instr_s;
                instr_id = tab[tempop].instr_id;
            }
            else{
                struct itab tab[] = {
                    { "fcvtpu", AD_INSTR_FCVTPU }, { "fcvtzu", AD_INSTR_FCVTZU },
                    { "ursqrte", AD_INSTR_URSQRTE }, { "frsqrte", AD_INSTR_FRSQRTE }
                };

                if(OOB(tempop, tab))
                    return 1;

                instr_s = tab[tempop].instr_s;
                instr_id = tab[tempop].instr_id;
            }
        }

        unsigned _sz = (size & 1);

        if(scalar && fp16){
            T = Q == 0 ? "4h" : "8h";

            rtbl = AD_RTBL_FP_16;
            sz = _16_BIT;
        }
        else if(scalar){
            rtbl = _sz == 0 ? AD_RTBL_FP_32 : AD_RTBL_FP_64;
            sz = _sz == 0 ? _32_BIT : _64_BIT;
        }
        else if(fp16){
            T = Q == 0 ? "4h" : "8h";

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
        else{
            if(_sz == 0)
                T = Q == 0 ? "2s" : "4s";
            else if(_sz == 1 && Q == 1){
                if(instr_id == AD_INSTR_URECPE || instr_id == AD_INSTR_URSQRTE)
                    return 1;

                T = "2d";
            }

            if(!T)
                return 1;

            rtbl = AD_RTBL_FP_V_128;
            sz = _128_BIT;
        }
    }

    if(!rtbl)
        return 1;

    const char *Rd_s = GET_FP_REG(rtbl, Rd);
    const char *Rn_s = GET_FP_REG(rtbl, Rn);

    ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(NONE), rtbl);

    concat(&DECODE_STR(out), "%s %s", instr_s, Rd_s);

    if(scalar)
        concat(&DECODE_STR(out), ", %s", Rn_s);
    else
        concat(&DECODE_STR(out), ".%s, %s.%s", T, Rn_s, T);

    if(add_zero){
        ADD_IMM_OPERAND(out, AD_INT, 0);
        concat(&DECODE_STR(out), ", #0");
    }
    else if(add_zerof){
        ADD_IMM_OPERAND(out, AD_FLOAT, 0);
        concat(&DECODE_STR(out), ", #0.0");
    }

    SET_INSTR_ID(out, instr_id);

    return 0;
}

/*
char *DisassembleAdvancedSIMDThreeDifferentInstr(struct instruction *instruction, int scalar){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int size = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int U = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *instr = NULL;
    char Va = '\0', Vb = '\0';
    const char *Ta = NULL, *Tb = NULL;

    char Va_s[] = {'\0', 's', 'd'};
    char Vb_s[] = {'\0', 'h', 's'};

    const char *Ta_s[] = {"8h", "4s", "2d"};

    const char *instr_tbl_u0[] = {"saddl", "saddw", "ssubl", "ssubw", "addhn", "sabal", 
        "subhn", "sabdl", "smlal", "sqdmlal", "smlsl", "sqdmlsl", 
        "smull", "sqdmull", "pmull"};
    const char *instr_tbl_u1[] = {"uaddl", "uaddw", "usubl", "usubw", "raddhn", "uabal",
        "rsubhn", "uabdl", "umlal", NULL, "umlsl", NULL, 
        "umull", NULL, NULL};

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u0)))
        return strdup(".undefined");

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u1)))
        return strdup(".undefined");

    instr = U == 0 ? instr_tbl_u0[opcode] : instr_tbl_u1[opcode];

    if(!instr)
        return strdup(".undefined");

    if(strstr(instr, "pmull"))
        Ta = size == 0 ? "8h" : "1q";
    else
        Ta = Ta_s[size];

    Tb = get_arrangement(size, Q);

    if(scalar){
        Va = Va_s[size];
        Vb = Vb_s[size];
    }

    disassembled = malloc(128);

    if(scalar)
        sprintf(disassembled, "%s %c%d, %c%d, %c%d", instr, Va, Rd, Vb, Rn, Vb, Rm);
    else
        sprintf(disassembled, "%s%s %s.%s, %s.%s, %s.%s", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb, ARM64_VectorRegisters[Rm], Tb);

    return disassembled;
}

int VFPExpandImm(int imm8){
    int E = 8, N = 32;

    const int F = N - E - 1;

    int sign = ((imm8 >> 7) & 1);
    int exp = (((imm8 >> 6) & 1) ^ 1) << ((E - 3) + 2) |
        _Replicate(((imm8 >> 6) & 1), 1, E - 3) << 2 |
        getbitsinrange(imm8, 4, 2);
    int frac = getbitsinrange(imm8, 0, 4) << (F - 4);

    return sign << ((1 + (E - 3) + 2) + (4 + (F - 4))) |
        exp << (4 + (F - 4)) |
        frac;
}

char *DisassembleAdvancedSIMDModifiedImmediateInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int h = getbitsinrange(instruction->opcode, 5, 1);
    unsigned int g = getbitsinrange(instruction->opcode, 6, 1);
    unsigned int f = getbitsinrange(instruction->opcode, 7, 1);
    unsigned int e = getbitsinrange(instruction->opcode, 8, 1);
    unsigned int d = getbitsinrange(instruction->opcode, 9, 1);
    unsigned int o2 = getbitsinrange(instruction->opcode, 11, 1);
    unsigned int cmode = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int c = getbitsinrange(instruction->opcode, 16, 1);
    unsigned int b = getbitsinrange(instruction->opcode, 17, 1);
    unsigned int a = getbitsinrange(instruction->opcode, 18, 1);
    unsigned int op = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *instr = NULL, *Vt = NULL, *T = NULL, *_Rd = NULL;
    const char *T_8[] = {"8b", "16b"};
    const char *T_16[] = {"4h", "8h"};
    const char *T_32[] = {"2s", "4s"};

    int amount_16[] = {0, 8};
    int amount_32_imm[] = {0, 8, 16, 24};
    int amount_32_ones[] = {8, 16};

    unsigned long imm8 = (a << 7) |
        (b << 6) |
        (c << 5) |
        (d << 4) |
        (e << 3) |
        (f << 2) |
        (g << 1) |
        h;

    int operation = (cmode << 1) | op;

    if(cmode != 0xf){
        unsigned long imm = _Replicate(a, 1, 8) << 56 |
            _Replicate(b, 1, 8) << 48 |
            _Replicate(c, 1, 8) << 40 |
            _Replicate(d, 1, 8) << 32 |
            _Replicate(e, 1, 8) << 24 |
            _Replicate(f, 1, 8) << 16 |
            _Replicate(g, 1, 8) << 8 |
            _Replicate(h, 1, 8);

        int shifts = 0, shift_amount = 0, use_imm = 0;
        const char *shift_str = NULL;

        if((operation & ~0xc) == 0)
            instr = "movi";
        else if((operation & ~0xc) == 1)
            instr = "mvni";
        else if((operation & ~0xc) == 2)
            instr = "orr";
        else if((operation & ~0xc) == 3)
            instr = "bic";
        else if((operation & ~0x4) == 0x10)
            instr = "movi";
        else if((operation & ~0x4) == 0x11)
            instr = "mvni";
        else if((operation & ~0x4) == 0x12)
            instr = "orr";
        else if((operation & ~0x4) == 0x13)
            instr = "bic";
        else if((operation & ~0x2) == 0x18)
            instr = "movi";
        else if((operation & ~0x2) == 0x19)
            instr = "mvni";
        else
            instr = "movi";

        if(strcmp(instr, "movi") == 0){
            if(op == 0){
                if(cmode != 0xe)
                    shift_str = (cmode & ~0x1) == 0xc ? "msl" : "lsl";

                if(cmode == 0xe)
                    T = T_8[Q];
                else if((cmode & ~0x2) == 0x8){
                    T = T_16[Q];
                    shift_amount = amount_16[((cmode >> 1) & 1)];
                }
                else{
                    T = T_32[Q];
                    shift_amount = (cmode & ~0x1) == 0xc ? amount_32_ones[(cmode & 1)] : amount_32_imm[getbitsinrange(cmode, 1, 2)];
                }

                _Rd = ARM64_VectorRegisters[Rd];
            }
            else{
                use_imm = 1;

                if(Q == 0)
                    _Rd = ARM64_VectorDoublePrecisionRegisters[Rd];
                else{
                    _Rd = ARM64_VectorRegisters[Rd];
                    T = "2d";
                }
            }
        }
        else if(strcmp(instr, "orr") == 0){
            shift_str = "lsl";

            if((cmode & ~0x2) == 0x9){
                T = T_16[Q];
                shift_amount = amount_16[((cmode >> 1) & 1)];
            }
            else{
                T = T_32[Q];
                shift_amount = amount_32_imm[getbitsinrange(cmode, 1, 2)];
            }

            _Rd = ARM64_VectorRegisters[Rd];
        }
        else if(strcmp(instr, "mvni") == 0){
            _Rd = ARM64_VectorRegisters[Rd];

            if((cmode & ~0x2) == 0x9){
                shift_str = "lsl";
                T = T_16[Q];
                shift_amount = amount_16[((cmode >> 1) & 1)];
            }
            else if((cmode & ~0x1) == 0xc){
                shift_str = "msl";
                T = T_32[Q];
                shift_amount = amount_32_ones[(cmode & 1)];
            }
            else{
                shift_str = "lsl";
                T = T_32[Q];
                shift_amount = amount_32_imm[getbitsinrange(cmode, 1, 2)];
            }
        }
        else{
            _Rd = ARM64_VectorRegisters[Rd];
            shift_str = "lsl";

            if((cmode & ~0x2) == 0x9){
                T = T_16[Q];
                shift_amount = amount_16[((cmode >> 1) & 1)];
            }
            else{
                T = T_32[Q];
                shift_amount = amount_32_imm[getbitsinrange(cmode, 1, 2)];
            }
        }

        if(shift_amount > 0)
            shifts = 1;

        disassembled = malloc(128);

        sprintf(disassembled, "%s %s", instr, _Rd);

        if(T)
            sprintf(disassembled, "%s.%s", disassembled, T);

        sprintf(disassembled, "%s, #%#lx", disassembled, use_imm ? imm : imm8);

        if(shifts)
            sprintf(disassembled, "%s, %s #%d", disassembled, shift_str, shift_amount);
    }
    else{
        instr = "fmov";
        _Rd = ARM64_VectorRegisters[Rd];

        if(op == 1)
            T = "2d";
        else if(o2 == 0)
            T = T_32[Q];
        else
            T = T_16[Q];

        int imm = VFPExpandImm(imm8);

        union intfloat {
            int i;
            float f;
        } _if;

        _if.i = imm;

        disassembled = malloc(128);
        sprintf(disassembled, "%s %s.%s, #%.1f", instr, _Rd, T, _if.f);
    }			

    return disassembled;
}

const char *get_shift_by_immediate_arrangement(unsigned int immh, unsigned int Q){
    if(immh == 1)
        return Q == 0 ? "8b" : "16b";
    else if((immh & ~0x1) == 2)
        return Q == 0 ? "4h" : "8h";
    else if((immh & ~0x3))
        return Q == 0 ? "2s" : "4s";
    else
        return Q == 0 ? NULL : "2d";
}

const char *get_shift_by_immediate_Ta(unsigned int immh){
    if(immh == 1)
        return "8h";
    else if((immh & ~0x1) == 2)
        return "4s";
    else if((immh & ~0x3) == 4)
        return "2d";
    else
        return NULL;
}

char get_shift_by_immediate_Vb(unsigned int immh){
    if(immh == 1)
        return 'b';
    else if((immh & ~0x1) == 2)
        return 'h';
    else if((immh & ~0x3) == 4)
        return 's';
    else
        return '\0';
}

char get_shift_by_immediate_Va(unsigned int immh){
    if(immh == 1)
        return 'h';
    else if((immh & ~0x1) == 2)
        return 's';
    else if((immh & ~0x3) == 4)
        return 'd';
    else
        return '\0';
}

char get_shift_by_immediate_V(unsigned int immh){
    if(immh == 1)
        return 'b';
    else if((immh & ~0x1) == 2)
        return 'h';
    else if((immh & ~0x3) == 4)
        return 's';
    else
        return 'd';
}

unsigned int get_shift_by_immediate_shift(unsigned int immh, unsigned int immb){
    unsigned int combined = (immh << 3) | immb;

    if(immh == 1)
        return combined - 8;
    else if((immh & ~0x1) == 2)
        return combined - 16;
    else if((immh & ~0x3) == 4)
        return combined - 32;
    else
        return combined - 64;
}

unsigned int get_shift_by_immediate_shift2(unsigned int immh, unsigned int immb){
    unsigned int combined = (immh << 3) | immb;

    if(immh == 1)
        return 16 - combined;
    else if((immh & ~0x1) == 2)
        return 32 - combined;
    else if((immh & ~0x3) == 4)
        return 64 - combined;
    else
        return 128 - combined;
}

char *DisassembleAdvancedSIMDShiftByImmediateInstr(struct instruction *instruction, int scalar){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 11, 5);
    unsigned int immb = getbitsinrange(instruction->opcode, 16, 3);
    unsigned int immh = getbitsinrange(instruction->opcode, 19, 4);
    unsigned int U = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *Vd = NULL, *Vn = NULL;
    char Va = '\0', Vb = '\0';
    const char *Ta = NULL, *Tb = NULL;
    const char *T = NULL;
    char V = '\0';
    unsigned int shift = 0;
    const char **instr_tbl = NULL;

    const char *instr_tbl_u0[] = {"sshr", NULL, "ssra", NULL, "srshr", NULL, "srsra",
        NULL, NULL, NULL, "shl", NULL, NULL, NULL, "sqshl",
        NULL, "shrn", "rshrn", "sqshrn", "sqrshrn", "sshll",
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, "scvtf",
        NULL, NULL, "fcvtzs"};
    const char *instr_tbl_u1[] = {"ushr", NULL, "usra", NULL, "urshr", NULL, "ursra",		
        NULL, "sri", NULL, "sli", NULL, "sqshlu", NULL, "uqshl",
        NULL, "sqshrun", "sqrshrun", "uqshrn", "uqrshrn",
        "ushll", NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        "ucvtf", NULL, NULL, "fcvtzu"};

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u0)))
        return strdup(".undefined");

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u1)))
        return strdup(".undefined");

    if(U == 0)
        instr_tbl = instr_tbl_u0;
    else
        instr_tbl = instr_tbl_u1;

    const char *instr = instr_tbl[opcode];

    if(!instr)
        return strdup(".undefined");

    if(opcode >= 0x10 && opcode <= 0x14){
        Vb = get_shift_by_immediate_Vb(immh);
        Va = get_shift_by_immediate_Va(immh);
        Tb = get_shift_by_immediate_arrangement(immh, Q);
        Ta = get_shift_by_immediate_Ta(immh);

        if(Va == '\0' || Vb == '\0' || !Tb || !Ta)
            return strdup(".undefined");

        shift = get_shift_by_immediate_shift2(immh, immb);

        disassembled = malloc(128);

        if(scalar)
            sprintf(disassembled, "%s %c%d, %c%d, #%#x", instr, Vb, Rd, Va, Rn, shift);
        else
            sprintf(disassembled, "%s%s %s.%s, %s.%s, #%#x", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Tb, ARM64_VectorRegisters[Rn], Ta, shift);
    }
    else{
        V = get_shift_by_immediate_V(immh);
        T = get_shift_by_immediate_arrangement(immh, Q);

        if(V == '\0' || !T)
            return strdup(".undefined");		

        if(strcmp(instr, "sshr") == 0 || strcmp(instr, "ushr") == 0
                || strcmp(instr, "ssra") == 0 || strcmp(instr, "usra") == 0
                || strcmp(instr, "srshr") == 0 || strcmp(instr, "urshr") == 0
                || strcmp(instr, "srsra") == 0 || strcmp(instr, "ursra") == 0
                || strcmp(instr, "sri") == 0){
            if((immh & ~0x7) == 0x8)
                shift = 128 - ((immh << 3) | immb);
            else
                return strdup(".undefined");
        }
        else if(strcmp(instr, "shl") == 0 || strcmp(instr, "sli") == 0){
            if((immh & ~0x7) == 0x8)
                shift = 64 - ((immh << 3) | immb);
            else
                return strdup(".undefined");
        }
        else if(strcmp(instr, "sqshl") == 0 || strcmp(instr, "sqshlu") == 0
                || strcmp(instr, "uqshl") == 0)
            shift = get_shift_by_immediate_shift(immh, immb);
        else if(strcmp(instr, "scvtf") == 0 || strcmp(instr, "fcvtzs") == 0
                || strcmp(instr, "ucvtf") == 0 || strcmp(instr, "fcvtzu") == 0)
            shift = get_shift_by_immediate_shift2(immh, immb);

        disassembled = malloc(128);

        if(scalar)
            sprintf(disassembled, "%s %c%d, %c%d, #%#x", instr, V, Rd, V, Rn, shift);
        else
            sprintf(disassembled, "%s %s.%s, %s.%s, #%#x", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, shift);
    }

    return disassembled;
}

char *DisassembleAdvancedSIMDIndexedElementInstr(struct instruction *instruction, int scalar){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int H = getbitsinrange(instruction->opcode, 11, 1);
    unsigned int opcode = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 4);
    unsigned int M = getbitsinrange(instruction->opcode, 20, 1);
    unsigned int L = getbitsinrange(instruction->opcode, 21, 1);
    unsigned int size = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int a = (size >> 1);
    unsigned int sz = (size & 1);
    unsigned int U = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *instr = NULL;
    const char *Va = NULL, *Vb = NULL, *Vm = NULL;
    const char *Vd = NULL, *Vn = NULL;
    char V = '\0';
    const char *Ta = NULL, *Tb = NULL, *Ts = NULL, *T = NULL;

    const char *instr_tbl_u0[] = {(size == 2) ? "fmlal" : NULL, 
        (size == 0 || (size >> 1) == 1) ? "fmla" : NULL,
        "smlal", "sqrdmlal",
        (size == 2) ? "fmlsl" : NULL,
        (size == 0 || (size >> 1) == 1) ? "fmls" : NULL,
        "smlsl", "sqdmlsl", "mul",
        (size == 0 || (size >> 1) == 1) ? "fmul" : NULL,
        "smull", "sqdmull", "sqdmulh", "sqrdmulh", "sdot"};

    const char *instr_tbl_u1[] = {"mla",
        (size == 1 || size == 2) ? "fcmla" : NULL,
        "umlal",
        (size == 1 || size == 2) ? "fcmla" : NULL,
        "mls",
        (size == 1 || size == 2) ? "fcmla" : NULL,
        "umlsl",
        (size == 1 || size == 2) ? "fcmla" : NULL,
        (size == 2) ? "fmlal" : NULL,
        (size == 0 || (size >> 1) == 1) ? "fmulx" : NULL,
        "umull", NULL,
        (size == 2) ? "fmlsl" : NULL,
        "sqrdmlah", "udot", "sqrdmlsh"};

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u0)))
        return strdup(".undefined");

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u1)))
        return strdup(".undefined");

    if(U == 0)
        instr = instr_tbl_u0[opcode];
    else
        instr = instr_tbl_u1[opcode];

    if(!instr)
        return strdup(".undefined");

    int index = -1;

    if((U == 0 && (opcode == 0 || opcode == 1
                    || opcode == 4 || opcode == 5
                    || opcode == 9)) || (U == 1 && (opcode == 2 || opcode == 3
                        || opcode == 6 || opcode == 7
                        || opcode == 10 || opcode == 11))){
        if(scalar){
            if(size == 0){
                index = (H << 2) | (L << 1) | M;

                disassembled = malloc(128);
                sprintf(disassembled, "%s %s, %s, %s.h[%d]", instr, ARM64_VectorHalfPrecisionRegisters[Rd], ARM64_VectorHalfPrecisionRegisters[Rn], ARM64_VectorRegisters[Rm], index);
            }
            else{
                V = sz == 0 ? 's' : 'd';
                Vm = ARM64_VectorRegisters[(M << 5) | Rm];
                Ts = sz == 0 ? "s" : "d";
                index = (((sz << 1) | L) >> 1) == 0 ? ((H << 1) | L) : H;

                disassembled = malloc(128);
                sprintf(disassembled, "%s %c%d, %c%d, %s.%s[%d]", instr, V, Rd, V, Rn, Vm, Ts, index);
            }
        }
        else{
            if(size == 0){
                index = (H << 2) | (L << 1) | M;
                T = Q == 0 ? "4h" : "8h";

                disassembled = malloc(128);
                sprintf(disassembled, "%s %s.%s, %s.%s, %s.h[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], index);
            }
            else{
                index = (((sz << 1) | L) >> 1) == 0 ? ((H << 1) | L) : H;

                T = Q == 0 ? "2s" : sz == 0 ? "4s" : "2d";
                Ts = sz == 0 ? "s" : "d";

                disassembled = malloc(128);
                sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], Ts, index);
            }
        }
    }
    else if((U == 0 && (opcode == 2 || opcode == 3
                    || opcode == 6 || opcode == 7
                    || opcode == 10 || opcode == 11))
            || (U == 1 && (opcode == 2 || opcode == 6
                    || opcode == 10))){
        if(scalar){
            index = size == 1 ? ((H << 2) | (L << 1) | M) : ((H << 1) | M);

            Va = size == 1 ? "s" : "d";
            Vb = size == 1 ? "h" : "s";
            Vm = size == 1 ? ARM64_VectorRegisters[(0 << 5) | Rm] : ARM64_VectorRegisters[(M << 5) | Rm];

            Ts = size == 1 ? "h" : "s";

            disassembled = malloc(128);
            sprintf(disassembled, "%s %s%d, %s%d, %s.%s[%d]", instr, Va, Rd, Vb, Rn, Vm, Ts, index);
        }
        else{
            index = size == 1 ? ((H << 2) | (L << 1) | M) : ((H << 1) | M);

            Ta = size == 1 ? "4s" : "2d";
            Tb = size == 1 ? Q == 0 ? "4h" : "8h" : Q == 0 ? "2s" : "4s";
            Ts = size == 1 ? "h" : "s";

            disassembled = malloc(128);
            sprintf(disassembled, "%s%s %s.%s, %s.%s, %s.%s[%d]", instr, Q == 1 ? "2" : "", ARM64_VectorRegisters[Rd], Ta, ARM64_VectorRegisters[Rn], Tb, ARM64_VectorRegisters[Rm], Ts, index);
        }
    }
    else{
        if(scalar){
            V = size == 1 ? 'h' : 's';
            Ts = size == 1 ? "h" : "s";
            index = size == 1 ? ((H << 2) | (L << 1) | M) : ((H << 1) | M);

            disassembled = malloc(128);
            sprintf(disassembled, "%s %c%d, %c%d, %s.%s[%d]", instr, V, Rd, V, Rn, ARM64_VectorRegisters[Rm], Ts, index);
        }
        else{
            T = size == 1 ? Q == 0 ? "4h" : "8h" : Q == 0 ? "2s" : "4s";
            Ts = size == 1 ? "h" : "s";
            index = size == 1 ? (H << 2) | (L << 1) | M : (H << 1) | M;

            disassembled = malloc(128);
            sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], Ts, index);
        }
    }

    if(strcmp(instr, "fcmla") == 0)
        sprintf(disassembled, "%s, #%d", disassembled, 90*(int)getbitsinrange(instruction->opcode, 13, 2));

    if(!disassembled)
        return strdup(".unknown");

    return disassembled;
}

char *DisassembleAdvancedSIMDScalarPairwiseInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 12, 5);
    unsigned int size = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int sz = (size & 1);
    unsigned int U = getbitsinrange(instruction->opcode, 29, 1);

    const char *instr = NULL, *T = NULL;
    char V = '\0';

    if(opcode == 0x1b){
        if(U == 1)
            return strdup(".undefined");

        instr = "addp";

        if(size != 3)
            return strdup(".undefined");

        V = 'd';
        T = "2d";
    }
    else{
        // subtract 12 so we don't have to deal with rows of annoying NULL
        opcode -= 12;

        if(U == 0){
            if(size == 0){
                const char *tbl[] = {"fmaxnmp", "faddp", NULL, "fmaxp"};
                if(!check_bounds(opcode, ARRAY_SIZE(tbl)))
                    return strdup(".undefined");

                instr = tbl[opcode];
            }
            else if(size == 2){
                const char *tbl[] = {"fminnmp", NULL, NULL, "fminp"};
                if(!check_bounds(opcode, ARRAY_SIZE(tbl)))
                    return strdup(".undefined");

                instr = tbl[opcode];
            }
            else
                return strdup(".undefined");

            V = 'h';
            T = "2h";
        }
        else{
            if((size >> 1) == 0){
                const char *tbl[] = {"fmaxnmp", "faddp", NULL, "fmaxp"};
                if(!check_bounds(opcode, ARRAY_SIZE(tbl)))
                    return strdup(".undefined");

                instr = tbl[opcode];
            }
            else if((size >> 1) == 1){
                const char *tbl[] = {"fminnmp", NULL, NULL, "fminp"};
                if(!check_bounds(opcode, ARRAY_SIZE(tbl)))
                    return strdup(".undefined");

                instr = tbl[opcode];
            }
            else
                return strdup(".undefined");

            V = sz == 0 ? 's' : 'd';
            T = sz == 0 ? "2s" : "2d";
        }
    }

    disassembled = malloc(128);
    sprintf(disassembled, "%s %c%d, %s.%s", instr, V, Rd, ARM64_VectorRegisters[Rn], T);

    return disassembled;
}

char *DisassembleAdvancedSIMDTableLookupInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int op = getbitsinrange(instruction->opcode, 12, 1);
    unsigned int len = getbitsinrange(instruction->opcode, 13, 2);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int op2 = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *instr = NULL;
    len++;

    if(op == 0)
        instr = "tbl";
    else
        instr = "tbx";

    const char *Ta = Q == 0 ? "8b" : "16b";

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s.%s, {", instr, ARM64_VectorRegisters[Rd], Ta);

    for(int i=Rn; i<(Rn+len); i++)
        sprintf(disassembled, "%s%s.16b, ", disassembled, ARM64_VectorRegisters[i]);

    disassembled[strlen(disassembled) - 2] = '\0';

    sprintf(disassembled, "%s}, %s.%s", disassembled, ARM64_VectorRegisters[Rm], Ta);

    return disassembled;
}

char *DisassembleAdvancedSIMDPermuteInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 12, 3);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int size = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    if(opcode == 0 || opcode == 4)
        return strdup(".undefined");

    const char *instr_tbl[] = {NULL, "uzp1", "trn1", "zip1", NULL, "uzp2", "trn2", "zip2"};
    const char *instr = instr_tbl[opcode];

    const char *T = get_arrangement(size, Q);

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T);

    return disassembled;
}

char *DisassembleAdvancedSIMDExtractInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm4 = getbitsinrange(instruction->opcode, 11, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *T = Q == 0 ? "8b" : "16b";

    unsigned int index = 0;

    if(Q == 0 && ((imm4 >> 3) & 1) == 0)
        index = getbitsinrange(imm4, 0, 3);
    else
        index = imm4;

    disassembled = malloc(128);
    sprintf(disassembled, "ext %s.%s, %s.%s, %s.%s, #%d", ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T, index);

    return disassembled;
}

const char *get_advanced_SIMD_copy_arrangement(unsigned int imm5, unsigned int Q){
    if((imm5 & 1) == 1)
        return Q == 0 ? "8b" : "16b";
    else if(((imm5 >> 1) & 1) == 1)
        return Q == 0 ? "4h" : "8h";
    else if(((imm5 >> 2) & 1) == 1)
        return Q == 0 ? "2s" : "4s";
    else if(((imm5 >> 3) & 1) == 1)
        return Q == 0 ? NULL : "2d";
    else
        return NULL;
}

const char *get_advanced_SIMD_copy_specifier(unsigned int imm5){
    if((imm5 & 1) == 1)
        return "b";
    else if(((imm5 >> 1) & 1) == 1)
        return "h";
    else if(((imm5 >> 2) & 1) == 1)
        return "s";
    else if(((imm5 >> 3) & 1) == 1)
        return "d";
    else
        return NULL;
}

char get_advanced_SIMD_gen_width_specifier(unsigned int imm5){
    if((imm5 & 1) == 1)
        return 'w';
    else if(((imm5 >> 1) & 1) == 1)
        return 'w';
    else if(((imm5 >> 2) & 1) == 1)
        return 'w';
    else if(((imm5 >> 3) & 1) == 1)
        return 'x';
    else
        return '\0';
}

unsigned int get_advanced_SIMD_copy_index(unsigned int imm5){
    if((imm5 & 1) == 1)
        return getbitsinrange(imm5, 1, 4);
    else if(((imm5 >> 1) & 1) == 1)
        return getbitsinrange(imm5, 2, 3);
    else if(((imm5 >> 2) & 1) == 1)
        return getbitsinrange(imm5, 3, 2);
    else if(((imm5 >> 3) & 1) == 1)
        return getbitsinrange(imm5, 4, 1);
    else
        return -1;
}

char *DisassembleAdvancedSIMDCopyInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm4 = getbitsinrange(instruction->opcode, 11, 4);
    unsigned int imm5 = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int op = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *instr = NULL;
    const char *T = NULL, *Ts = NULL;
    unsigned int index = 0;
    char V = '\0', R = '\0';

    T = get_advanced_SIMD_copy_arrangement(imm5, Q);
    Ts = get_advanced_SIMD_copy_specifier(imm5);
    index = get_advanced_SIMD_copy_index(imm5);
    R = get_advanced_SIMD_gen_width_specifier(imm5);		

    if(!T || !Ts || index == -1 || R == '\0')
        return strdup(".undefined");

    if(imm4 == 0 || imm4 == 1){
        disassembled = malloc(128);

        if(imm4 == 0)
            sprintf(disassembled, "dup %s.%s, %s.%s[%d]", ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], Ts, index);
        else
            sprintf(disassembled, "dup %s.%s, %c%d", ARM64_VectorRegisters[Rd], T, R, Rn);
    }
    else if(imm4 == 5){
        disassembled = malloc(128);

        if(Q == 0)
            sprintf(disassembled, "smov %s, %s.%s[%d]", ARM64_32BitGeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);
        else
            sprintf(disassembled, "smov %s, %s.%s[%d]", ARM64_GeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);
    }
    else if(imm4 == 7){
        disassembled = malloc(128);

        if(Q == 0){
            const char *instr = "umov";

            if(((imm5 >> 2) & 1) == 1)
                instr = "mov";

            sprintf(disassembled, "%s %s, %s.%s[%d]", instr, ARM64_32BitGeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);
        }
        else{
            const char *instr = "umov";

            if(((imm5 >> 3) & 1) == 1)
                instr = "mov";

            sprintf(disassembled, "%s %s, %s.%s[%d]", instr, ARM64_GeneralRegisters[Rd], ARM64_VectorRegisters[Rn], Ts, index);	
        }
    }
    else{
        disassembled = malloc(128);

        if(op == 0)
            sprintf(disassembled, "mov %s.%s[%d], %c%d", ARM64_VectorRegisters[Rd], Ts, index, R, Rn);
        else{
            unsigned int index1 = index;
            unsigned int index2 = 0;

            if((imm5 & 1) == 1)
                index2 = getbitsinrange(imm4, 0, 4);
            else if(((imm5 >> 1) & 1) == 1)
                index2 = getbitsinrange(imm4, 1, 3);
            else if(((imm5 >> 2) & 1) == 1)
                index2 = getbitsinrange(imm4, 2, 2);
            else if(((imm5 >> 3) & 1) == 1)
                index2 = getbitsinrange(imm4, 3, 1);

            sprintf(disassembled, "mov %s.%s[%d], %s.%s[%d]", ARM64_VectorRegisters[Rd], Ts, index1, ARM64_VectorRegisters[Rn], Ts, index2);
        }
    }

    return disassembled;
}

char *DisassembleAdvancedSIMDAcrossLanesInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 12, 5);
    unsigned int size = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int sz = (size & 1);
    unsigned int U = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int Q = getbitsinrange(instruction->opcode, 30, 1);

    const char *instr = NULL;

    const char *instr_tbl_u0[] = {NULL, NULL, NULL, "saddlv", NULL, NULL,
        NULL, NULL, NULL, NULL, "smaxv", NULL,
        (size == 0) ? "fmaxnmv" : "fminnmv",
        NULL, NULL,
        (size == 0) ? "fmaxv" : "fminv",
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        "sminv", "addv"};
    const char *instr_tbl_u1[] = {NULL, NULL, NULL, "addlv", NULL, NULL,
        NULL, NULL, NULL, NULL, "umaxv", NULL,
        ((size >> 1) == 0) ? "fmaxnmv" : "fminnmv",
        NULL, NULL,
        ((size >> 1) == 0) ? "fmaxv" : "fminv",
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        "uminv", NULL};

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u0)))
        return strdup(".undefined");

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl_u1)))
        return strdup(".undefined");

    const char *T = NULL;
    char V = '\0';

    char V_tbl[] = {'b', 'h', 's'};
    char V_tbl2[] = {'h', 's', 'd'};

    if(U == 0)
        instr = instr_tbl_u0[opcode];
    else
        instr = instr_tbl_u1[opcode];

    if(opcode == 3){
        V = V_tbl2[size];
        T = get_arrangement(size, Q);
    }
    else if(opcode == 12 || opcode == 15){
        V = U == 0 ? 'h' : 's';
        T = get_arrangement2(U == 0, sz, Q);
    }
    else{
        V = V_tbl[size];
        T = get_arrangement(size, Q);
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %c%d, %s.%s", instr, V, Rd, ARM64_VectorRegisters[Rn], T);

    return disassembled;
}

char *DisassembleCryptographicThreeRegisterImm2(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 10, 2);
    unsigned int imm2 = getbitsinrange(instruction->opcode, 12, 2);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);

    const char *instr_tbl[] = {"sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b"};
    const char *instr = instr_tbl[opcode];

    const char *T = "4s";

    if(strcmp(instr, "sm3tt2b") == 0)
        T = "s";

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s.%s, %s.%s, %s.s[%d]", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], imm2);

    return disassembled;
}

char *DisassembleCryptographicThreeRegisterSHA512Instr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 10, 2);
    unsigned int O = getbitsinrange(instruction->opcode, 14, 1);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);

    const char *instr_tbl_O0[] = {"sha512h", "sha512h2", "sha512su1", "rax1"};
    const char *instr_tbl_O1[] = {"sm3partw1", "sm3partw2", "sm4ekey", NULL};

    const char *instr = NULL;

    if(O == 0)
        instr = instr_tbl_O0[opcode];
    else
        instr = instr_tbl_O1[opcode];

    if(!instr)
        return strdup(".undefined");

    char *_Rd = malloc(32);
    char *_Rn = malloc(32);
    char *_Rm = malloc(32);

    if(strcmp(instr, "sha512h") == 0 || strcmp(instr, "sha512h2") == 0){
        sprintf(_Rd, "q%d", Rd);
        sprintf(_Rn, "q%d", Rn);
        sprintf(_Rm, "v%d.2d", Rm);
    }
    else if(strcmp(instr, "sha512su1") == 0 || strcmp(instr, "rax1") == 0){
        sprintf(_Rd, "v%d.2d", Rd);
        sprintf(_Rn, "v%d.2d", Rn);
        sprintf(_Rm, "v%d.2d", Rm);
    }
    else{
        sprintf(_Rd, "v%d.4s", Rd);
        sprintf(_Rn, "v%d.4s", Rn);
        sprintf(_Rm, "v%d.4s", Rm);
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

    free(_Rd);
    free(_Rn);
    free(_Rm);

    return disassembled;
}

char *DisassembleCryptographicFourRegisterInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int Ra = getbitsinrange(instruction->opcode, 10, 5);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int Op0 = getbitsinrange(instruction->opcode, 21, 2);

    if(Op0 == 3)
        return strdup(".undefined");

    const char *instr_tbl[] = {"eor3", "bcax", "sm3ss1"};
    const char *instr = instr_tbl[Op0];

    const char *T = "16b";

    if(Op0 == 2)
        T = "4s";

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s.%s, %s.%s, %s.%s, %s.%s", instr, ARM64_VectorRegisters[Rd], T, ARM64_VectorRegisters[Rn], T, ARM64_VectorRegisters[Rm], T, ARM64_VectorRegisters[Ra], T);

    return disassembled;
}

char *DisassembleXARInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm6 = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);

    disassembled = malloc(128);

    sprintf(disassembled, "xar %s.2d, %s.2d, %s.2d, #%#x", ARM64_VectorRegisters[Rd], ARM64_VectorRegisters[Rn], ARM64_VectorRegisters[Rm], imm6);

    return disassembled;
}

char *DisassembleCryptographicTwoRegisterSHA512Instr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 10, 2);

    disassembled = malloc(128);

    if(opcode == 0)
        sprintf(disassembled, "sha512su0 %s.2d, %s.2d", ARM64_VectorRegisters[Rd], ARM64_VectorRegisters[Rn]);
    else if(opcode == 1)
        sprintf(disassembled, "sm4e %s.4s, %s.4s", ARM64_VectorRegisters[Rd], ARM64_VectorRegisters[Rn]);
    else{
        free(disassembled);
        return strdup(".undefined");
    }

    return disassembled;
}

char *DisassembleConversionBetweenFloatingPointAndFixedPointInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int scale = getbitsinrange(instruction->opcode, 10, 6);
    unsigned int opcode = getbitsinrange(instruction->opcode, 16, 3);
    unsigned int rmode = getbitsinrange(instruction->opcode, 19, 2);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char *instr_tbl[] = {"fcvtzs", "fcvtzu", "scvtf", "ucvtf"};
    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
        return strdup(".undefined");

    const char *instr = instr_tbl[opcode];

    unsigned int fbits = 64 - scale;

    char *_Rd = malloc(24);
    char *_Rn = malloc(24);

    if(strcmp(instr, "scvtf") == 0 || strcmp(instr, "ucvtf") == 0){
        if(type == 3)
            sprintf(_Rd, "h%d", Rd);
        else if(type == 0)
            sprintf(_Rd, "s%d", Rd);
        else if(type == 1)
            sprintf(_Rd, "d%d", Rd);
        else{
            free(_Rd);
            free(_Rn);
            return strdup(".undefined");
        }

        if(sf == 0)
            sprintf(_Rn, "w%d", Rn);
        else
            sprintf(_Rn, "x%d", Rn);
    }
    else{
        if(type == 3)
            sprintf(_Rn, "h%d", Rn);
        else if(type == 0)
            sprintf(_Rn, "s%d", Rn);
        else if(type == 1)
            sprintf(_Rn, "d%d", Rn);
        else{
            free(_Rd);
            free(_Rn);
            return strdup(".undefined");
        }

        if(sf == 0)
            sprintf(_Rd, "w%d", Rd);
        else
            sprintf(_Rd, "x%d", Rd);
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s, #%#x", instr, _Rd, _Rn, fbits);

    return disassembled;
}

char *DisassembleConversionBetweenFloatingPointAndIntegerInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 16, 3);
    unsigned int rmode = getbitsinrange(instruction->opcode, 19, 2);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int sf = getbitsinrange(instruction->opcode, 31, 1);

    const char *instr = NULL;

    char *_Rd = malloc(32);
    char *_Rn = malloc(32);

    if(sf == 0 && S == 0 && type == 0 && rmode == 0){
        const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 0 && rmode == 1){
        const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 0 && rmode == 2){
        const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 0 && rmode == 3){
        const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 1 && rmode == 0){
        const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 1 && rmode == 1){
        const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 1 && rmode == 2){
        const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 1 && rmode == 3){
        const char *instr_tbl[] = {"fcvtzs", "fcvtzu", NULL, NULL, NULL, NULL, "fjcvtzs"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 3 && rmode == 0){
        const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 3 && rmode == 1){
        const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 3 && rmode == 2){
        const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 0 && S == 0 && type == 3 && rmode == 3){
        const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 0 && rmode == 0){
        const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 0 && rmode == 1){
        const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 0 && rmode == 2){
        const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 0 && rmode == 3){
        const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 1 && rmode == 0){
        const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 1 && rmode == 1){
        const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 1 && rmode == 2){
        const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 1 && rmode == 3){
        const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 2 && rmode == 1){
        const char *instr_tbl[] = {NULL, NULL, NULL, NULL, NULL, NULL, "fmov", "fmov", NULL};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 3 && rmode == 0){
        const char *instr_tbl[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 3 && rmode == 1){
        const char *instr_tbl[] = {"fcvtps", "fcvtpu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 3 && rmode == 2){
        const char *instr_tbl[] = {"fcvtms", "fcvtmu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else if(sf == 1 && S == 0 && type == 3 && rmode == 3){
        const char *instr_tbl[] = {"fcvtzs", "fcvtzu"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");
        instr = instr_tbl[opcode];
    }
    else{
        free(_Rd);
        free(_Rn);
        return strdup(".undefined");
    }

    if(!instr)
        return strdup(".undefined");

    if(strstr(instr, "fcvt") || strcmp(instr, "fjcvtzs") == 0){
        if(type == 3)
            sprintf(_Rn, "h%d", Rn);
        else if(type == 0)
            sprintf(_Rn, "s%d", Rn);
        else if(type == 1)
            sprintf(_Rn, "d%d", Rn);
        else{
            free(_Rd);
            free(_Rn);
            return strdup(".undefined");
        }

        if(sf == 0)
            sprintf(_Rd, "w%d", Rd);
        else
            sprintf(_Rd, "x%d", Rd);
    }
    else if(strcmp(instr, "fmov") != 0){
        if(type == 3)
            sprintf(_Rd, "h%d", Rd);
        else if(type == 0)
            sprintf(_Rd, "s%d", Rd);
        else if(type == 1)
            sprintf(_Rd, "d%d", Rd);
        else{
            free(_Rd);
            free(_Rn);
            return strdup(".undefined");
        }

        if(sf == 0)
            sprintf(_Rn, "w%d", Rn);
        else
            sprintf(_Rn, "x%d", Rn);
    }
    else if(strcmp(instr, "fmov") == 0){
        if(sf == 0 && type == 3 && rmode == 0 && opcode == 6){
            sprintf(_Rd, "w%d", Rd);
            sprintf(_Rn, "h%d", Rn);
        }
        else if(sf == 1 && type == 3 && rmode == 0 && opcode == 6){
            sprintf(_Rd, "x%d", Rd);
            sprintf(_Rn, "h%d", Rn);
        }
        else if(sf == 0 && type == 3 && rmode == 0 && opcode == 7){
            sprintf(_Rd, "h%d", Rd);
            sprintf(_Rn, "w%d", Rn);
        }
        else if(sf == 0 && type == 0 && rmode == 0 && opcode == 7){
            sprintf(_Rd, "s%d", Rd);
            sprintf(_Rn, "w%d", Rn);
        }
        else if(sf == 0 && type == 0 && rmode == 0 && opcode == 6){
            sprintf(_Rd, "w%d", Rd);
            sprintf(_Rn, "s%d", Rn);
        }
        else if(sf == 1 && type == 3 && rmode == 0 && opcode == 7){
            sprintf(_Rd, "h%d", Rd);
            sprintf(_Rn, "x%d", Rn);
        }
        else if(sf == 1 && type == 1 && rmode == 0 && opcode == 7){
            sprintf(_Rd, "d%d", Rd);
            sprintf(_Rn, "x%d", Rn);
        }
        else if(sf == 1 && type == 2 && rmode == 1 && opcode == 7){
            sprintf(_Rd, "v%d.d[1]", Rd);
            sprintf(_Rn, "x%d", Rn);
        }
        else if(sf == 1 && type == 1 && rmode == 0 && opcode == 6){
            sprintf(_Rd, "x%d", Rd);
            sprintf(_Rn, "d%d", Rn);
        }
        else if(sf == 1 && type == 2 && rmode == 1 && opcode == 6){
            sprintf(_Rd, "x%d", Rd);
            sprintf(_Rn, "v%d.d[1]", Rn);
        }
        else
            return strdup(".undefined");

        if(strcmp(_Rn, "w31") == 0)
            strcpy(_Rn, "#0.0");
        else if(strcmp(_Rn, "x31") == 0)
            strcpy(_Rn, "#0.0");
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);

    free(_Rd);
    free(_Rn);

    return disassembled;
}

char *DisassembleFloatingPointDataProcessingOneSource(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 15, 6);
    unsigned int opc = getbitsinrange(instruction->opcode, 15, 2);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    const char *instr = NULL;

    char *_Rd = malloc(32);
    char *_Rn = malloc(32);

    if(M == 0 && S == 0 && type == 0){
        const char *instr_tbl[] = {"fmov", "fabs", "fneg", "fsqrt", NULL, "fcvt", NULL, "fcvt",
            "frintn", "frintp", "frintm", "frintz", "frinta", NULL, "frintx", "frinti"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");

        instr = instr_tbl[opcode];
    }
    else if(M == 0 && S == 0 && type == 1){
        const char *instr_tbl[] = {"fmov", "fabs", "fneg", "fsqrt", "fcvt", NULL, NULL, "fcvt",
            "frintn", "frintp", "frintm", "frintz", "frinta", NULL, "frintx", "frinti"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");

        instr = instr_tbl[opcode];
    }
    else if(M == 0 && S == 0 && type == 3){
        const char *instr_tbl[] = {"fmov", "fabs", "fneg", "fsqrt", "fcvt", "fcvt", NULL, NULL,
            "frintn", "frintp", "frintm", "frintz", "frinta", NULL, "frintx", "frinti"};
        if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
            return strdup(".undefined");

        instr = instr_tbl[opcode];
    }
    else{
        free(_Rd);
        free(_Rn);
        return strdup(".undefined");
    }

    if(!instr)
        return strdup(".undefined");

    if(strcmp(instr, "fcvt") == 0){
        if(type == 3){
            if(opc == 0){
                sprintf(_Rd, "s%d", Rd);
                sprintf(_Rn, "h%d", Rn);
            }
            else{
                sprintf(_Rd, "d%d", Rd);
                sprintf(_Rn, "h%d", Rn);
            }
        }
        else if(type == 0){
            if(opc == 3){
                sprintf(_Rd, "h%d", Rd);
                sprintf(_Rn, "s%d", Rn);
            }
            else{
                sprintf(_Rd, "d%d", Rd);
                sprintf(_Rn, "s%d", Rn);
            }
        }
        else if(type == 1){
            if(opc == 3){
                sprintf(_Rd, "h%d", Rd);
                sprintf(_Rn, "d%d", Rn);
            }
            else{
                sprintf(_Rd, "s%d", Rd);
                sprintf(_Rn, "d%d", Rn);
            }
        }
        else{
            free(_Rd);
            free(_Rn);
            return strdup(".undefined");
        }
    }
    else{
        if(type == 3){
            sprintf(_Rd, "h%d", Rd);
            sprintf(_Rn, "h%d", Rn);
        }
        else if(type == 0){
            sprintf(_Rd, "s%d", Rd);
            sprintf(_Rn, "s%d", Rn);
        }
        else if(type == 1){
            sprintf(_Rd, "d%d", Rd);
            sprintf(_Rn, "d%d", Rn);
        }
        else{
            free(_Rd);
            free(_Rn);
            return strdup(".undefined");
        }
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s", instr, _Rd, _Rn);

    free(_Rd);
    free(_Rn);

    return disassembled;
}

char *DisassembleFloatingPointCompareInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int opcode2 = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int opc = getbitsinrange(instruction->opcode, 3, 2);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int op = getbitsinrange(instruction->opcode, 14, 2);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    const char *instr = NULL;

    if((opc >> 1) == 0)
        instr = "fcmp";
    else
        instr = "fcmpe";

    char *_Rn = malloc(32);
    char *_Rm = malloc(32);

    if(type == 3){
        sprintf(_Rn, "h%d", Rn);

        if(Rm == 0 && (opc == 1 || opc == 3))
            sprintf(_Rm, "#0.0");
        else
            sprintf(_Rm, "h%d", Rm);
    }
    else if(type == 0){
        sprintf(_Rn, "s%d", Rn);

        if(Rm == 0 && (opc == 1 || opc == 3))
            sprintf(_Rm, "#0.0");
        else
            sprintf(_Rm, "s%d", Rm);
    }
    else if(type == 1){
        sprintf(_Rn, "d%d", Rn);

        if(Rm == 0 && (opc == 1 || opc == 3))
            sprintf(_Rm, "#0.0");
        else
            sprintf(_Rm, "d%d", Rm);
    }
    else{
        free(_Rn);
        free(_Rm);
        return strdup(".undefined");
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s", instr, _Rn, _Rm);

    free(_Rn);
    free(_Rm);

    return disassembled;
}


char *DisassembleFloatingPointImmediateInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int imm5 = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int imm8 = getbitsinrange(instruction->opcode, 13, 8);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    const char *_Rd = NULL;

    if(type == 3)
        _Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
    else if(type == 0)
        _Rd = ARM64_VectorSinglePrecisionRegisters[Rd];
    else if(type == 1)
        _Rd = ARM64_VectorDoublePrecisionRegisters[Rd];

    int imm = VFPExpandImm(imm8);

    union intfloat {
        int i;
        float f;
    } _if;

    _if.i = imm;

    disassembled = malloc(128);

    sprintf(disassembled, "fmov %s, #%.1f", _Rd, _if.f);

    return disassembled;
}

char *DisassembleFloatingPointConditionalCompare(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int nzcv = getbitsinrange(instruction->opcode, 0, 4);
    unsigned int op = getbitsinrange(instruction->opcode, 4, 1);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int cond = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    const char *instr = NULL;

    if(op == 0)
        instr = "fccmp";
    else
        instr = "fccmpe";

    char *_Rn = malloc(32);
    char *_Rm = malloc(32);

    if(type == 3){
        sprintf(_Rn, "h%d", Rn);
        sprintf(_Rm, "h%d", Rm);
    }
    else if(type == 0){
        sprintf(_Rn, "s%d", Rn);
        sprintf(_Rm, "s%d", Rm);
    }
    else if(type == 1){
        sprintf(_Rn, "d%d", Rn);
        sprintf(_Rm, "d%d", Rm);
    }
    else{
        free(_Rn);
        free(_Rm);
        return strdup(".undefined");
    }

    char *_cond = decode_cond(cond);

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s, #%#x, %s", instr, _Rn, _Rm, nzcv, _cond);

    free(_Rn);
    free(_Rm);
    free(_cond);

    return disassembled;
}

char *DisassembleFloatingPointDataProcessingTwoSourceInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int opcode = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    if(M == 1)
        return strdup(".undefined");

    const char *instr_tbl[] = {"fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"};

    if(!check_bounds(opcode, ARRAY_SIZE(instr_tbl)))
        return strdup(".undefined");

    const char *instr = instr_tbl[opcode];

    const char *_Rd = NULL, *_Rn = NULL, *_Rm = NULL;

    if(type == 3){
        _Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
        _Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
        _Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
    }
    else if(type == 0){
        _Rd = ARM64_VectorSinglePrecisionRegisters[Rd];
        _Rn = ARM64_VectorSinglePrecisionRegisters[Rn];
        _Rm = ARM64_VectorSinglePrecisionRegisters[Rm];
    }
    else if(type == 1){
        _Rd = ARM64_VectorDoublePrecisionRegisters[Rd];
        _Rn = ARM64_VectorDoublePrecisionRegisters[Rn];
        _Rm = ARM64_VectorDoublePrecisionRegisters[Rm];
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s, %s", instr, _Rd, _Rn, _Rm);

    return disassembled;
}

char *DisassembleFloatingPointConditionalSelectInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int cond = getbitsinrange(instruction->opcode, 12, 4);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    const char *_Rd = NULL, *_Rn = NULL, *_Rm = NULL;

    if(type == 3){
        _Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
        _Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
        _Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
    }
    else if(type == 0){
        _Rd = ARM64_VectorSinglePrecisionRegisters[Rd];
        _Rn = ARM64_VectorSinglePrecisionRegisters[Rn];
        _Rm = ARM64_VectorSinglePrecisionRegisters[Rm];
    }
    else if(type == 1){
        _Rd = ARM64_VectorDoublePrecisionRegisters[Rd];
        _Rn = ARM64_VectorDoublePrecisionRegisters[Rn];
        _Rm = ARM64_VectorDoublePrecisionRegisters[Rm];
    }

    char *_cond = decode_cond(cond);

    disassembled = malloc(128);

    sprintf(disassembled, "fcsel %s, %s, %s, %s", _Rd, _Rn, _Rm, _cond);

    free(_cond);

    return disassembled;
}

char *DisassembleFloatingPointDataProcessingThreeSourceInstr(struct instruction *instruction){
    char *disassembled = NULL;

    unsigned int Rd = getbitsinrange(instruction->opcode, 0, 5);
    unsigned int Rn = getbitsinrange(instruction->opcode, 5, 5);
    unsigned int Ra = getbitsinrange(instruction->opcode, 10, 5);
    unsigned int o0 = getbitsinrange(instruction->opcode, 15, 1);
    unsigned int Rm = getbitsinrange(instruction->opcode, 16, 5);
    unsigned int o1 = getbitsinrange(instruction->opcode, 21, 1);
    unsigned int type = getbitsinrange(instruction->opcode, 22, 2);
    unsigned int S = getbitsinrange(instruction->opcode, 29, 1);
    unsigned int M = getbitsinrange(instruction->opcode, 31, 1);

    unsigned int encoding = (o1 << 1) | o0;

    const char *instr_tbl[] = {"fmadd", "fmsub", "fnmadd", "fnmsub"};
    const char *instr = instr_tbl[encoding];

    const char *_Rd = NULL, *_Rn = NULL, *_Rm = NULL, *_Ra = NULL;

    if(type == 3){
        _Rd = ARM64_VectorHalfPrecisionRegisters[Rd];
        _Rn = ARM64_VectorHalfPrecisionRegisters[Rn];
        _Rm = ARM64_VectorHalfPrecisionRegisters[Rm];
        _Ra = ARM64_VectorHalfPrecisionRegisters[Ra];
    }
    else if(type == 0){
        _Rd = ARM64_VectorSinglePrecisionRegisters[Rd];
        _Rn = ARM64_VectorSinglePrecisionRegisters[Rn];
        _Rm = ARM64_VectorSinglePrecisionRegisters[Rm];
        _Ra = ARM64_VectorSinglePrecisionRegisters[Ra];
    }
    else if(type == 1){
        _Rd = ARM64_VectorDoublePrecisionRegisters[Rd];
        _Rn = ARM64_VectorDoublePrecisionRegisters[Rn];
        _Rm = ARM64_VectorDoublePrecisionRegisters[Rm];
        _Ra = ARM64_VectorDoublePrecisionRegisters[Ra];
    }

    disassembled = malloc(128);

    sprintf(disassembled, "%s %s, %s, %s, %s", instr, _Rd, _Rn, _Rm, _Ra);

    return disassembled;
}
*/

int DataProcessingFloatingPointDisassemble(struct instruction *i,
        struct ad_insn *out){
    int result = 0;

    unsigned op0 = bits(i->opcode, 28, 31);
    unsigned op1 = bits(i->opcode, 23, 24);
    unsigned op2 = bits(i->opcode, 19, 22);
    unsigned op3 = bits(i->opcode, 10, 18);

    //printf("%s: op0 %d op1 %d op2 %d op3 %d\n", __func__, op0,op1,op2,op3);

    if(op0 == 4 && (op1 & ~1) == 0 && (op2 & ~8) == 5 && (op3 & ~0x7c) == 2)
        result = DisassembleCryptographicAESInstr(i, out);
    else if(op0 == 5 && (op1 & ~1) == 0 && (op2 & ~11) == 0 && (op3 & ~0x1dc) == 0)
        result = DisassembleCryptographicThreeRegisterSHAInstr(i, out);
    else if(op0 == 5 && (op1 & ~1) == 0 && (op2 & ~8) == 5 && (op3 & ~0x7c) == 2)
        result = DisassembleCryptographicTwoRegisterSHAInstr(i, out);
    else if((op0 & ~2) == 5 && op1 == 0 && (op2 & ~3) == 0 && (op3 & ~0x1de) == 1)
        result = DisassembleAdvancedSIMDScalarCopyInstr(i, out);
    // XXX in between: else if ... DisassembleAdvancedSIMDCopyInstr
    else if(((op0 & ~2) == 5 || (op0 & ~6) == 0) &&
            (op1 & ~1) == 0 &&
            ((op2 & ~3) == 8 || (op2 & ~11) == 4 || (op2 & ~11) == 0) &&
            ((op3 & ~0x1ce) == 1 || (op3 & ~0x1de) == 0x21 || (op3 & ~0x1fe) == 1)){
        int scalar = (op0 & 1);
        int fp16 = (op2 >> 2) == 2 && (op3 & ~0x1ce) == 1;
        int extra = (op2 & ~11) == 0 && (op3 & ~0x1de) == 0x21;

        result = DisassembleAdvancedSIMDThreeSameInstr(i, out, scalar, fp16, extra);
    }
    else if(((op0 & ~2) == 5 || (op0 & ~6) == 0) &&
            (op1 & ~1) == 0 &&
            ((op2 == 0xf) || (op2 & ~8) == 4) &&
            (op3 & ~0x7c) == 2){
        int scalar = (op0 & 1);
        int fp16 = (op2 == 0xf);

        result = DisassembleAdvancedSIMDTwoRegisterMiscellaneousInstr(i, out, scalar, fp16);
    }
    else
        result = 1;

    return result;
    /*
    char *disassembled = NULL;

    unsigned int op3 = getbitsinrange(instruction->opcode, 10, 9);
    unsigned int op2 = getbitsinrange(instruction->opcode, 19, 4);
    unsigned int op1 = getbitsinrange(instruction->opcode, 23, 2);
    unsigned int op0 = getbitsinrange(instruction->opcode, 28, 4);

    if(op0 == 0x4 && (op1 >> 0x1) == 0 && (op2 & ~0x8) == 0x5 && (op3 & ~0x7c) == 0x2)
        disassembled = DisassembleCryptographicAESInstr(instruction);
    else if(op0 == 0x5 && (op1 >> 0x1) == 0 && (op2 & ~0xb) == 0 && (op3 & ~0x1dc) == 0)
        disassembled = DisassembleCryptographicThreeRegisterSHAInstr(instruction);
    else if(op0 == 0x5 && (op1 >> 0x1) == 0 && (op2 & ~0x8) == 0x5 && (op3 & ~0x7c) == 0x2)
        disassembled = DisassembleCryptographicTwoRegisterSHAInstr(instruction);
    else if((op0 & ~0x2) == 0x5 && op1 == 0 && (op2 & ~0x3) == 0 && (op3 & ~0x1de) == 0x1)
        disassembled = DisassembleAdvancedSIMDScalarCopyInstr(instruction);
    else if((op0 & ~0x6) == 0 && op1 == 0 && (op2 & ~0x3) == 0 && (op3 & ~0x1fe) == 0x1)
        disassembled = DisassembleAdvancedSIMDCopyInstr(instruction);
    else if(((op0 & ~0x2) == 0x5 || (op0 & ~0x6) == 0) && (op1 >> 0x1) == 0 && ((op2 & ~0xb) == 0 || (op2 & ~0xb) == 0x4) && ((op3 & ~0x1ce) == 0x1 || (op3 & ~0x1de) == 0x21 || (op3 & ~0x1fe) == 0x1)){
        int scalar = (op0 & 0x1);
        int fp16 = (op2 >> 0x2) == 0x2 && (((op3 >> 0x5) & 0x1) == 0 && ((op3 >> 0x4) & 0x1) == 0 && (op3 & 0x1) == 0x1);
        int extra = ((op2 >> 0x2) & 0x1) == 0 && (((op3 >> 0x5) & 0x1) == 0x1 && (op3 & 0x1) == 0x1);

        disassembled = DisassembleAdvancedSIMDThreeSameInstr(instruction, scalar, fp16, extra);
    }
    else if(((op0 & ~0x2) == 0x5 || (op0 & ~0x6) == 0) && (op1 >> 0x1) == 0 && (op2 == 0xf || (op2 & ~0x8) == 0x4) && (op3 & ~0x7c) == 0x2)
        disassembled = DisassembleAdvancedSIMDTwoRegisterMiscellaneousInstr(instruction, (op0 & 0x1), op2 == 0xf);
    else if(((op0 & ~0x2) == 0x5 || (op0 & ~0x6) == 0) && (op1 >> 0x1) == 0 && ((op2 >> 0x2) & 0x1) == 0x1 && (op3 & ~0x1fc) == 0)
        disassembled = DisassembleAdvancedSIMDThreeDifferentInstr(instruction, (op0 & 0x1));
    else if(((op0 & ~0x2) == 0x5 || (op0 & ~0x6) == 0) && op1 == 0x2 && (op3 & 0x1) == 0x1){
        int scalar = ((op0 & ~0x2) == 0x5);

        if(op2 == 0)
            disassembled = DisassembleAdvancedSIMDModifiedImmediateInstr(instruction);
        else
            disassembled = DisassembleAdvancedSIMDShiftByImmediateInstr(instruction, scalar);
    }
    else if(((op0 & ~0x2) == 0x5 || (op0 & ~0x6) == 0) && (op1 >> 0x1) == 0x1 && (op3 & 0x1) == 0)
        disassembled = DisassembleAdvancedSIMDIndexedElementInstr(instruction, ((op0 & ~0x2) == 0x5));
    else if((op0 & ~0x2) == 0x5 && (op1 >> 0x1) == 0 && (op2 & ~0x8) == 0x6 && (op3 & ~0x7c) == 0x2)
        disassembled = DisassembleAdvancedSIMDScalarPairwiseInstr(instruction);
    else if((op0 & ~0x4) == 0 && (op1 >> 0x1) == 0 && ((op2 >> 0x2) & 0x1) == 0 && (op3 & ~0x1dc) == 0)
        disassembled = DisassembleAdvancedSIMDTableLookupInstr(instruction);
    else if((op0 & ~0x4) == 0 && (op1 >> 0x1) == 0 && ((op2 >> 0x2) & 0x1) == 0 && (op3 & ~0x1dc) == 0x2)
        disassembled = DisassembleAdvancedSIMDPermuteInstr(instruction);
    else if((op0 & ~0x4) == 0x2 && (op1 >> 0x1) == 0 && ((op2 >> 0x2) & 0x1) == 0 && (op3 & ~0x1de) == 0)
        disassembled = DisassembleAdvancedSIMDExtractInstr(instruction);
    else if((op0 & ~0x6) == 0 && (op1 >> 0x1) == 0 && (op2 & ~0x8) == 0x6 && (op3 & ~0x7c) == 0x2)
        disassembled = DisassembleAdvancedSIMDAcrossLanesInstr(instruction);
    else if(op0 == 0xc && op1 == 0 && (op2 >> 0x2) == 0x2 && (op3 & ~0x1cf) == 0x20)
        disassembled = DisassembleCryptographicThreeRegisterImm2(instruction);
    else if(op0 == 0xc && op1 == 0 && (op2 >> 0x2) == 0x3 && (op3 & ~0x1d3) == 0x20)
        disassembled = DisassembleCryptographicThreeRegisterSHA512Instr(instruction);
    else if(op0 == 0xc && op1 == 0 && (op3 & ~0x1df) == 0)
        disassembled = DisassembleCryptographicFourRegisterInstr(instruction);
    else if(op0 == 0xc && op1 == 0x1 && (op2 & ~0x3) == 0)
        disassembled = DisassembleXARInstr(instruction);
    else if(op0 == 0xc && op1 == 0x1 && op2 == 0x8 && (op3 & ~0x23) == 0x20)
        disassembled = DisassembleCryptographicTwoRegisterSHA512Instr(instruction);
    else if((op0 & ~0xa) == 0x1 && (op1 >> 0x1) == 0 && (op2 & ~0xb) == 0)
        disassembled = DisassembleConversionBetweenFloatingPointAndFixedPointInstr(instruction);
    else if((op0 & ~0xa) == 0x1 && (op1 >> 0x1) == 0 && (op2 & ~0xb) == 0x4){
        if((op3 & ~0x1c0) == 0)
            disassembled = DisassembleConversionBetweenFloatingPointAndIntegerInstr(instruction);
        else if((op3 & ~0x1e0) == 0x10)
            disassembled = DisassembleFloatingPointDataProcessingOneSource(instruction);
        else if((op3 & ~0x1f0) == 0x8)
            disassembled = DisassembleFloatingPointCompareInstr(instruction);
        else if((op3 & ~0x1f8) == 0x4)
            disassembled = DisassembleFloatingPointImmediateInstr(instruction);
        else if((op3 & ~0x1fc) == 0x1)
            disassembled = DisassembleFloatingPointConditionalCompare(instruction);
        else if((op3 & ~0x1fc) == 0x2)
            disassembled = DisassembleFloatingPointDataProcessingTwoSourceInstr(instruction);
        else if((op3 & ~0x1fc) == 0x3)
            disassembled = DisassembleFloatingPointConditionalSelectInstr(instruction);
        else
            return strdup(".undefined");
    }
    else if((op0 & ~0xa) == 0x1 && (op1 >> 0x1) == 0x1)
        disassembled = DisassembleFloatingPointDataProcessingThreeSourceInstr(instruction);
    else
        return strdup(".undefined");

    return disassembled;
    */
}
