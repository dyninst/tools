
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
    addReplaceTerm(*fl, "st(0)", "mm0");
    addReplaceTerm(*fl, "st(1)", "mm1");
    addReplaceTerm(*fl, "st(2)", "mm2");
    addReplaceTerm(*fl, "st(3)", "mm3");
    addReplaceTerm(*fl, "st(4)", "mm4");
    addReplaceTerm(*fl, "st(5)", "mm5");
    addReplaceTerm(*fl, "st(6)", "mm6");
    addReplaceTerm(*fl, "st(7)", "mm7");
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
    addOperandSwapTerm(*fl, "vextract", 1, 2);
    addOperandSwapTerm(*fl, "fcmovbe", 1, 2);
    addOperandSwapTerm(*fl, "pcmp", 1, 2);
    addOperandSwapTerm(*fl, "pextrd", 1, 2);
    addOperandSwapTerm(*fl, "pshulw", 1, 2);
    addOperandSwapTerm(*fl, "lgs", 1, 2);
    addOperandSwapTerm(*fl, "lss", 1, 2);
    addOperandSwapTerm(*fl, "enter", 1, 2);
    addOperandSwapTerm(*fl, "shld", 1, 2);
    addOperandSwapTerm(*fl, "shrd", 1, 2);
    addOperandSwapTerm(*fl, "pmulhw", 1, 2);
    addOperandSwapTerm(*fl, "vor", 1, 2);
    addOperandSwapTerm(*fl, "vmax", 1, 2);
    addOperandSwapTerm(*fl, "vmin", 1, 2);
    //addOperandSwapTerm(*fl, "vpsll", 1, 2);
    addOperandSwapTerm(*fl, "vpsrad", 1, 2);
    addOperandSwapTerm(*fl, "vpor", 1, 2);
    addOperandSwapTerm(*fl, "vpxor", 1, 2);
    addOperandSwapTerm(*fl, "vpab", 1, 2);
    addOperandSwapTerm(*fl, "vphadd", 1, 2);
    addOperandSwapTerm(*fl, "vpmov", 1, 2);
    addOperandSwapTerm(*fl, "vpsra", 1, 2);
    addOperandSwapTerm(*fl, "vpsrld", 1, 2);
    addOperandSwapTerm(*fl, "vmask", 1, 2);
    addOperandSwapTerm(*fl, "vexp", 1, 2);
    addOperandSwapTerm(*fl, "vrcp", 1, 2);
    addOperandSwapTerm(*fl, "vrange", 1, 2);

    addOperandSwapTerm(*fl, "vunpck", 1, 2);
    */
    return fl;
}

FindList* initVecSwapFindList() {
    FindList* fl = new FindList(877);
    //addOperandSwapTerm(*fl, "vshuf", 1, 3);
    // addOperandSwapTerm(*fl, "vsub", 1, 2); // evex diff
    //addOperandSwapTerm(*fl, "vadd", 1, 2);
    addOperandSwapTerm(*fl, "vmax", 1, 2);
    addOperandSwapTerm(*fl, "vmin", 1, 2);
    addOperandSwapTerm(*fl, "vdiv", 1, 2);
    addOperandSwapTerm(*fl, "vpand", 1, 2);
    addOperandSwapTerm(*fl, "vpadd", 1, 2);
    addOperandSwapTerm(*fl, "vfmadd", 1, 2);
    addOperandSwapTerm(*fl, "vfmsub", 1, 2);
    // addOperandSwapTerm(*fl, "vget", 1, 2); // evex diff
    addOperandSwapTerm(*fl, "vpinsr", 1, 3);
    // addOperandSwapTerm(*fl, "vpermil", 1, 3); // evex difft
    addOperandSwapTerm(*fl, "valign", 1, 3);
    // addOperandSwapTerm(*fl, "vgather", 1, 3); // evex diff
    //addOperandSwapTerm(*fl, "vinsert", 1, 3);
    addOperandSwapTerm(*fl, "vfixup", 1, 3);
    addOperandSwapTerm(*fl, "vshuff", 1, 3);
    addOperandSwapTerm(*fl, "vptern", 1, 3);
    addOperandSwapTerm(*fl, "vpalign", 1, 3);
    // addOperandSwapTerm(*fl, "vgetman", 1, 3); // evex diff
    // addOperandSwapTerm(*fl, "vreduce", 1, 3); // evex diff
    // addOperandSwapTerm(*fl, "vrnd", 1, 3);
    addOperandSwapTerm(*fl, "vdbp", 1, 3);
    addOperandSwapTerm(*fl, "vpxor", 1, 2);
    // addOperandSwapTerm(*fl, "vpsll", 1, 2);
    addOperandSwapTerm(*fl, "vpack", 1, 2);
    addOperandSwapTerm(*fl, "vpavg", 1, 2);
    addOperandSwapTerm(*fl, "vpsad", 1, 2);
    addOperandSwapTerm(*fl, "vpsub", 1, 2);
    // addOperandSwapTerm(*fl, "vunpck", 1, 2); // evex right
    addOperandSwapTerm(*fl, "vphsub", 1, 2);
    addOperandSwapTerm(*fl, "vpmul", 1, 2);
    addOperandSwapTerm(*fl, "vpmadd", 1, 2);
    addOperandSwapTerm(*fl, "vpcmp", 1, 2);
    // addOperandSwapTerm(*fl, "vperm", 1, 2);
    addOperandSwapTerm(*fl, "vpmax", 1, 2);
    addOperandSwapTerm(*fl, "vmwrite", 1, 2);
    //addOperandSwapTerm(*fl, "vmul", 1, 2);
    //addOperandSwapTerm(*fl, "vmov", 1, 2);
    addOperandSwapTerm(*fl, "vpunpck", 1, 2);
    addOperandSwapTerm(*fl, "vpinsr", 1, 2);
    // addOperandSwapTerm(*fl, "vpmin", 1, 2);
    addOperandSwapTerm(*fl, "vphadd", 1, 2);
    addOperandSwapTerm(*fl, "vpxor", 1, 2);
    // addOperandSwapTerm(*fl, "vor", 1, 2);
    // addOperandSwapTerm(*fl, "vxor", 1, 2);
    addOperandSwapTerm(*fl, "vpor", 1, 2);
    // addOperandSwapTerm(*fl, "vpgather", 1, 2);
    // addOperandSwapTerm(*fl, "vfnmadd", 1, 2);
    // addOperandSwapTerm(*fl, "vfnmsub", 1, 2);
    addOperandSwapTerm(*fl, "vand", 1, 2);
    // addOperandSwapTerm(*fl, "vpsr", 1, 2); // evex right
    // addOperandSwapTerm(*fl, "vpshuf", 1, 2);
    // addOperandSwapTerm(*fl, "vpex", 1, 2);
    return fl;
}

FindList* initSwapAlwaysFindList() {
    FindList* fl = new FindList(877);
    addOperandSwapTerm(*fl, "cmpps", 1, 2);
    //addOperandSwapTerm(*fl, "shufps", 1, 2);
    //addOperandSwapTerm(*fl, "pshuf", 1, 3);
    addOperandSwapTerm(*fl, "pinsr", 1, 2);
    
    addOperandSwapTerm(*fl, "imul", 1, 2);
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
    //addReplaceTerm(*fl, "bq ", "b ");
    addReplaceTerm(*fl, "{%k0}", "");
    addReplaceTerm(*fl, "pminsl ", "pminsd ");
    addReplaceTerm(*fl, "movhps/movlhps", "movlhps");
    addReplaceTerm(*fl, "movlps/movhlps ", "movlps ");
    addReplaceTerm(*fl, "pinsrd/pinsrq ", "pinsrd ");
    addReplaceTerm(*fl, "pextrd/pextrq ", "pextrd ");
    addReplaceTerm(*fl, "pushfd ", "pushfq ");
    addReplaceTerm(*fl, "popfd ", "popfq ");
    //addReplaceTerm(*fl, "imul ", "imull ");
    addReplaceTerm(*fl, "insd ", "insl ");
    addReplaceTerm(*fl, "cmpxch", "cmpxchg");
    addReplaceTerm(*fl, "outsd ", "outsl ");
    addReplaceTerm(*fl, "lodsd ", "lodsl ");
    addReplaceTerm(*fl, "stosd ", "stosl ");
    addReplaceTerm(*fl, "scasd ", "scasl ");
    addReplaceTerm(*fl, "jmpq ", "jmp ");
    addReplaceTerm(*fl, "prefetchnta $", "prefetchnta ");
    addReplaceTerm(*fl, "movsd $", "movsd ");
    addReplaceTerm(*fl, "rcpss $", "rcpss ");
    addReplaceTerm(*fl, "sqrtsd $", "sqrtsd ");
    addReplaceTerm(*fl, "comiss $", "comiss ");
    addReplaceTerm(*fl, "stmxcsr $", "stmxcsr ");
    addReplaceTerm(*fl, "loopn %ecx, ", "loopne ");
    addReplaceTerm(*fl, "loopn %cx, ", "loopne ");
    addReplaceTerm(*fl, "loop %ecx, ", "loop ");
    addReplaceTerm(*fl, "loop %cx, ", "loop ");
    addReplaceTerm(*fl, "loope %ecx, ", "loope ");
    addReplaceTerm(*fl, "jcxz %ecx, ", "jrcxz ");
    addReplaceTerm(*fl, "cdq %eax", "cdq");
    addReplaceTerm(*fl, "ret far (%rsp)", "lret");
    addReplaceTerm(*fl, "ret near (%rsp)", "ret");
    addReplaceTerm(*fl, "int 3", "int3");
    addReplaceTerm(*fl, "shl/sal", "shl");
    addReplaceTerm(*fl, "fsave", "fnsave");
    addReplaceTerm(*fl, "fstenv", "fnstenv");
    addReplaceTerm(*fl, "fld ", "fldt ");
    addReplaceTerm(*fl, "fcmovbe ", "fcmovbe %st(0), ");
    addReplaceTerm(*fl, "vucomiss %ymm0, ", "vucomiss ");
    addReplaceTerm(*fl, "vucomisd %ymm0, ", "vucomisd ");
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

void dyninst_x86_64_norm(char* buf, int bufLen) {
    toLowerCase(buf, bufLen);
    removeUnusedStar(buf, bufLen);
    removeUnusedRepPrefixes(buf, bufLen);
    cleanSpaces(buf, bufLen);
    signedDisplacements(buf, bufLen);
    signedOperands(buf, bufLen);
    cleanX86NOP(buf, bufLen);
    fixStRegs(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    removeImplicitST0(buf, bufLen);
    removeImplicitFlags(buf, bufLen);
    removeImplicitRIP(buf, bufLen);
    formatSegRegs(buf, bufLen);
    fixDyninstMnemonics(buf, bufLen);
    dyninstSTToMM(buf, bufLen);
    swapEnterOperands(buf, bufLen);
    removeImplicitMulOperands(buf, bufLen);
    //trimHexFs(buf, bufLen);
    //trimHexZeroes(buf, bufLen);
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
    return 0;
}
