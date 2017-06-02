
/*
 * See fleece/COPYRIGHT for copyright information.
 *
 * This file is a part of Fleece.
 *
 * Fleece is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License, or (at your option)
 * any later version.
 *  
 * This software is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, see www.gnu.org/licenses
*/

#include <iomanip>
#include <string>
#include "Decoder.h"
#include "InstructionDecoder.h"
#include "Normalization.h"
#include "StringUtils.h"

using namespace Dyninst;
using namespace InstructionAPI;

void signedDisplacements(char* buf, int bufLen) {
    char* cur = buf;
    char* place;
    while (*cur) {
        if (*cur == '0' && *(cur + 1) == 'x') {
            place = cur;
            cur += 2;
            while (isxdigit(*cur)) {
                ++cur;
            }
            long long disp = strtoll(place, NULL, 16);
            int intDisp = (int)strtol(place, NULL, 16);
            if (*cur == '(' && (cur == place + 18 && disp < 0)) {
                disp = disp * -1;
                char temp[bufLen - (cur - buf)];
                strcpy(temp, cur);
                snprintf(place, bufLen - (place - buf), "-0x%x%s", (int)disp, temp);
            } else if (*cur == '(' && (cur == place + 10 && intDisp < 0)) {
                intDisp = intDisp * -1;
                char temp[bufLen - (cur - buf)];
                strcpy(temp, cur);
                snprintf(place, bufLen - (place - buf), "-0x%x%s", intDisp, temp);
            }
        }
        ++cur;
    }
}

void removeImplicitFlags(char* buf, int bufLen) {
    std::string result(buf);
   
    removeAtSubStr(result, ", %flags", 8);
    removeAtSubStr(result, "%flags", 6);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
}

void removeImplicitMulOperands(char* buf, int bufLen) {
    std::string result(buf);
   
    if (result.find("mul") == std::string::npos) {
        return;
    }

    removeAtSubStr(result, ", %al, %ax", 10);
    removeAtSubStr(result, ", %ax, %dx", 10);
    removeAtSubStr(result, ", %eax, %edx", 12);
    removeAtSubStr(result, ", %rax, %rdx", 12);
   
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
}

void removeImplicitRIP(char* buf, int bufLen) {
    std::string result(buf);
   
    if (strncmp(buf, "call", 4) && result.find(" call") == std::string::npos &&
        *buf != 'j' && result.find(" j") == std::string::npos && 
        strncmp(buf, "loop", 4) && result.find(" loop") == std::string::npos) {
        return;
    }

    removeAtSubStr(result, "(%rip)", 6);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
}

void formatSegRegs(char* buf, int bufLen) {
    char* cur = buf;
    while (*cur) {
        while (*cur && *cur != '(') {
            ++cur;
        }
        if (!*cur) {
            return;
        }
        if (*(cur + 1) == '%' && *(cur + 3) == 's' && *(cur + 4) == ',') {
            char* place = cur;
            while (place > buf && *place != ' ') {
                place--;
            }
            if (place == buf) {
                return;
            }
            place++;
            size_t len = cur - place;
            char tmp[len + 1];
            strncpy(tmp, place, len);
            tmp[len] = '\0';
            char seg = *(cur + 2);
            len = bufLen - (buf - (cur + 9));
            char rem[len];
            strncpy(rem, cur + 9, len);
            snprintf(place, bufLen - (buf - place), "%%%cs:(%%%s)%s", seg, tmp, rem);
            cur = place + 6;
        } else {
            ++cur;
        }
    }
}

FindList* initDyninstSTToMMFindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "st(0)", "mm0");
    Normalization::addReplaceTerm(*fl, "st(1)", "mm1");
    Normalization::addReplaceTerm(*fl, "st(2)", "mm2");
    Normalization::addReplaceTerm(*fl, "st(3)", "mm3");
    Normalization::addReplaceTerm(*fl, "st(4)", "mm4");
    Normalization::addReplaceTerm(*fl, "st(5)", "mm5");
    Normalization::addReplaceTerm(*fl, "st(6)", "mm6");
    Normalization::addReplaceTerm(*fl, "st(7)", "mm7");
    return fl;
}

void dyninstSTToMM(char* buf, int bufLen) {
    static FindList* fl = initDyninstSTToMMFindList();
    std::string result(buf);
     
    if (*buf != 'p' || result.find(" f") != std::string::npos) {
        return;
    }
    fl->process(buf, bufLen);
}

FindList* initSwapWithFirstMemOperandsFindList() {
    FindList* fl = new FindList(877);
    /*
    Normalization::addOperandSwapTerm(*fl, "vextract", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "fcmovbe", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "pcmp", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "pextrd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "pshulw", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "lgs", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "lss", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "shld", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "shrd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "pmulhw", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vor", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vmax", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vmin", 1, 2);
    //Normalization::addOperandSwapTerm(*fl, "vpsll", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpsrad", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpor", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpxor", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpab", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vphadd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpmov", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpsra", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpsrld", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vmask", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vexp", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vrcp", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vrange", 1, 2);

    Normalization::addOperandSwapTerm(*fl, "vunpck", 1, 2);
    */
    return fl;
}

FindList* initVecSwapFindList() {
    FindList* fl = new FindList(877);
    //Normalization::addOperandSwapTerm(*fl, "vshuf", 1, 3);
    // Normalization::addOperandSwapTerm(*fl, "vsub", 1, 2); // evex diff
    //Normalization::addOperandSwapTerm(*fl, "vadd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vmax", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vmin", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vdiv", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpand", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpadd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vfmadd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vfmsub", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vget", 1, 2); // evex diff
    Normalization::addOperandSwapTerm(*fl, "vpinsr", 1, 3);
    // Normalization::addOperandSwapTerm(*fl, "vpermil", 1, 3); // evex difft
    Normalization::addOperandSwapTerm(*fl, "valign", 1, 3);
    // Normalization::addOperandSwapTerm(*fl, "vgather", 1, 3); // evex diff
    //Normalization::addOperandSwapTerm(*fl, "vinsert", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "vfixup", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "vshuff", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "vptern", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "vpalign", 1, 3);
    // Normalization::addOperandSwapTerm(*fl, "vgetman", 1, 3); // evex diff
    // Normalization::addOperandSwapTerm(*fl, "vreduce", 1, 3); // evex diff
    // Normalization::addOperandSwapTerm(*fl, "vrnd", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "vdbp", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "vpxor", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vpsll", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpack", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpavg", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpsad", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpsub", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vunpck", 1, 2); // evex right
    Normalization::addOperandSwapTerm(*fl, "vphsub", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpmul", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpmadd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpcmp", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vperm", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpmax", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vmwrite", 1, 2);
    //Normalization::addOperandSwapTerm(*fl, "vmul", 1, 2);
    //Normalization::addOperandSwapTerm(*fl, "vmov", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpunpck", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpinsr", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vpmin", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vphadd", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpxor", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vor", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vxor", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vpor", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vpgather", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vfnmadd", 1, 2); // normal vex right, evex swapped
    // Normalization::addOperandSwapTerm(*fl, "vfnmsub", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vand", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vpsr", 1, 2); // evex right
    // Normalization::addOperandSwapTerm(*fl, "vpshuf", 1, 2);
    // Normalization::addOperandSwapTerm(*fl, "vpex", 1, 2);
    return fl;
}

FindList* initSwapAlwaysFindList() {
    FindList* fl = new FindList(877);
    Normalization::addOperandSwapTerm(*fl, "cmpps", 1, 2);
    //Normalization::addOperandSwapTerm(*fl, "shufps", 1, 2);
    //Normalization::addOperandSwapTerm(*fl, "pshuf", 1, 3);
    Normalization::addOperandSwapTerm(*fl, "pinsr", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "enter", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "imul", 1, 2);
    return fl;
}

void swapEnterOperands(char* buf, int bufLen) {
    static FindList* fl1 = initSwapWithFirstMemOperandsFindList();
    static FindList* fl2 = initSwapAlwaysFindList();
    static FindList* vecSwapFl = initVecSwapFindList();
    fl2->process(buf, bufLen);
    std::string str = std::string(buf);
    if (*buf == 'v' || str.find(" v") != std::string::npos) {
        vecSwapFl->process(buf, bufLen);
        return;
    }
    if (str.find("{") == std::string::npos && str.find(", 0x") == std::string::npos && str.find(", -0x") == std::string::npos) {
        return;
    }
    fl1->process(buf, bufLen);
}

FindList* initDyninstMnemonicsFindList() {
    FindList* fl = new FindList(877);
    //Normalization::addReplaceTerm(*fl, "bq ", "b ");
    Normalization::addReplaceTerm(*fl, "{%k0}", "");
    Normalization::addReplaceTerm(*fl, "vporlv", "vprolv");
    Normalization::addReplaceTerm(*fl, "pcmpgdt ", "pcmpgtd ");
    Normalization::addReplaceTerm(*fl, "minsl ", "minsd ");
    Normalization::addReplaceTerm(*fl, "punpcklqd ", "punpckldq ");
    Normalization::addReplaceTerm(*fl, "movhps/movlhps", "movlhps");
    Normalization::addReplaceTerm(*fl, "movlps/movhlps ", "movlps ");
    Normalization::addReplaceTerm(*fl, "pinsrd/pinsrq ", "pinsrd ");
    Normalization::addReplaceTerm(*fl, "pextrd/pextrq ", "pextrd ");
    Normalization::addReplaceTerm(*fl, "pushfd ", "pushfq ");
    Normalization::addReplaceTerm(*fl, "popfd ", "popfq ");
    //Normalization::addReplaceTerm(*fl, "imul ", "imull ");
    Normalization::addReplaceTerm(*fl, "insd ", "insl ");
    Normalization::addReplaceTerm(*fl, "cmpxch", "cmpxchg");
    Normalization::addReplaceTerm(*fl, "outsd ", "outsl ");
    Normalization::addReplaceTerm(*fl, "lodsd ", "lodsl ");
    Normalization::addReplaceTerm(*fl, "stosd ", "stosl ");
    Normalization::addReplaceTerm(*fl, "scasd ", "scasl ");
    Normalization::addReplaceTerm(*fl, "jmpq ", "jmp ");
    Normalization::addReplaceTerm(*fl, "prefetchnta $", "prefetchnta ");
    Normalization::addReplaceTerm(*fl, "movsd $", "movsd ");
    Normalization::addReplaceTerm(*fl, "rcpss $", "rcpss ");
    Normalization::addReplaceTerm(*fl, "sqrtsd $", "sqrtsd ");
    Normalization::addReplaceTerm(*fl, "comiss $", "comiss ");
    Normalization::addReplaceTerm(*fl, "stmxcsr $", "stmxcsr ");
    Normalization::addReplaceTerm(*fl, "loopn ", "loopne ");
    Normalization::addReplaceTerm(*fl, "loopne %ecx, ", "loopne ");
    Normalization::addReplaceTerm(*fl, "loopne %cx, ", "loopne ");
    Normalization::addReplaceTerm(*fl, "loopn %ecx, ", "loopne ");
    Normalization::addReplaceTerm(*fl, "loopn %cx, ", "loopne ");
    Normalization::addReplaceTerm(*fl, "loop %ecx, ", "loop ");
    Normalization::addReplaceTerm(*fl, "loop %cx, ", "loop ");
    Normalization::addReplaceTerm(*fl, "loope %ecx, ", "loope ");
    Normalization::addReplaceTerm(*fl, "jcxz %ecx, ", "jrcxz ");
    Normalization::addReplaceTerm(*fl, "cdq %eax", "cdq");
    Normalization::addReplaceTerm(*fl, "ret far (%rsp)", "lret");
    Normalization::addReplaceTerm(*fl, "ret near (%rsp)", "ret");
    Normalization::addReplaceTerm(*fl, "int 3", "int3");
    Normalization::addReplaceTerm(*fl, "shl/sal", "shl");
    Normalization::addReplaceTerm(*fl, "fsave", "fnsave");
    Normalization::addReplaceTerm(*fl, "fstenv", "fnstenv");
    Normalization::addReplaceTerm(*fl, "fld ", "fldt ");
    Normalization::addReplaceTerm(*fl, "fcmovbe ", "fcmovbe %st(0), ");
    Normalization::addReplaceTerm(*fl, "vucomiss %ymm0, ", "vucomiss ");
    Normalization::addReplaceTerm(*fl, "vucomisd %ymm0, ", "vucomisd ");
    return fl;
}

void fixDyninstMnemonics(char* buf, int bufLen) {
    static FindList* fl = initDyninstMnemonicsFindList();
    fl->process(buf, bufLen);
}

void removeUnusedStar(char* buf, int bufLen) {
    char* cur = buf;
    while(*cur) {
        if (*cur == '*') {
            *cur = ' ';
        }
        ++cur;
    }
}

/*
 * Removes all implicit operands from the memory compare and exchange instructions.
 *
 * Input:  cmpxchg8b $-0x4882a00d, ebx(%ecx, 22), eax(%edx, 22)
 * Output: cmpxchg8b $-0x4882a00d
 */ 
void removeImplicitCMPXCHGOperands(char* buf, int bufLen) {
    if (strncmp(buf, "cmpxchg8b", 9) && strncmp(buf, "cmpxchg16b", 10)) {
        return;
    }
    char* cur = buf;
    while (*cur && *cur != ',') {
        ++cur;
    }
    if (*cur) {
        *cur = '\0';
    }
}

void dyninst_x86_norm(char* buf, int bufLen) {
    //removeUnusedStar(buf, bufLen);
    //removeUnusedRepPrefixes(buf, bufLen);
    //signedDisplacements(buf, bufLen);
    //signedOperands(buf, bufLen);
    //cleanX86NOP(buf, bufLen);
    //fixStRegs(buf, bufLen);
    //removeImplicitST0(buf, bufLen);
    //removeImplicitFlags(buf, bufLen);
    //removeImplicitRIP(buf, bufLen);
    //removeImplicitCMPXCHGOperands(buf, bufLen);
    //formatSegRegs(buf, bufLen);
    //fixDyninstMnemonics(buf, bufLen);
    //dyninstSTToMM(buf, bufLen);
    //swapEnterOperands(buf, bufLen);
    //removeImplicitMulOperands(buf, bufLen);
}

int dyninst_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {

    if (nBytes < 1) {
        return -1;
    }

    if (inst[0] == (char)0x0F && inst[1] == (char)0x38 && inst[2] == (char)0xf3) {
        strncpy(buf, "would_sig", bufLen);
        return 0;
    }

    InstructionDecoder d = InstructionDecoder(inst, nBytes, Arch_x86_64);
    Instruction::Ptr p = d.decode();
    InstructionAPI::Instruction* insn_ptr = p.get();
    assert(insn_ptr);

    strncpy(buf, insn_ptr->format().c_str(), bufLen);
    
    // Sometimes when it fails to decode a register completely, Dyninst will
    // produce a decoder that ends in a '%' sign. Often, these correspond to
    // invalid instructions, and that seems like the most sensible way to
    // treat them, so the decoder returns an error if it cannot completely
    // decode a register.
    while (*buf) {
        ++buf;
    }
    if (*(buf - 1) == '%') {
        return -1;
    }
    return 0;
}
int dyninst_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {

    if (nBytes < 1) {
        return -1;
    }

    if (inst[0] == (char)0x0F && inst[1] == (char)0x38 && inst[2] == (char)0xf3) {
        strncpy(buf, "would_sig", bufLen);
        return 0;
    }

    InstructionDecoder d = InstructionDecoder(inst, nBytes, Arch_x86);
    Instruction::Ptr p = d.decode();
    InstructionAPI::Instruction* insn_ptr = p.get();
    assert(insn_ptr);

    strncpy(buf, insn_ptr->format().c_str(), bufLen);
    return 0;
}
Decoder* dec_dyninst_x86_32 = new Decoder(&dyninst_x86_32_decode, NULL, 
            &dyninst_x86_norm, "dyninst", "x86_32");
Decoder* dec_dyninst_x86_64 = new Decoder(&dyninst_x86_64_decode, NULL, 
            &dyninst_x86_norm, "dyninst", "x86_64");
