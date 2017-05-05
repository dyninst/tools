
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

FindList* initSwapEnterOperandsFindList() {
    FindList* fl = new FindList(877);
    addOperandSwapTerm(*fl, "vpex", 0, 1);
    addOperandSwapTerm(*fl, "vperm", 0, 1);
    addOperandSwapTerm(*fl, "vextract", 0, 1);
    addOperandSwapTerm(*fl, "vfnmsub", 0, 1);
    addOperandSwapTerm(*fl, "vfmsub", 0, 1);
    addOperandSwapTerm(*fl, "fcmovbe", 0, 1);
    addOperandSwapTerm(*fl, "pinsrb", 0, 1);
    addOperandSwapTerm(*fl, "pcmp", 0, 1);
    addOperandSwapTerm(*fl, "pextrd", 0, 1);
    addOperandSwapTerm(*fl, "pshulw", 0, 1);
    addOperandSwapTerm(*fl, "lgs", 0, 1);
    addOperandSwapTerm(*fl, "lss", 0, 1);
    addOperandSwapTerm(*fl, "enter", 0, 1);
    addOperandSwapTerm(*fl, "mul", 0, 1);
    addOperandSwapTerm(*fl, "shld", 0, 1);
    addOperandSwapTerm(*fl, "shrd", 0, 1);
    addOperandSwapTerm(*fl, "pmulhw", 0, 1);
    addOperandSwapTerm(*fl, "vor", 0, 1);
    addOperandSwapTerm(*fl, "vand", 0, 1);
    addOperandSwapTerm(*fl, "vsub", 0, 1);
    addOperandSwapTerm(*fl, "vadd", 0, 1);
    addOperandSwapTerm(*fl, "vmul", 0, 1);
    addOperandSwapTerm(*fl, "vshuf", 0, 1);
    addOperandSwapTerm(*fl, "vpunpck", 0, 1);
    addOperandSwapTerm(*fl, "vpack", 0, 1);
    addOperandSwapTerm(*fl, "vpsll", 0, 1);
    addOperandSwapTerm(*fl, "vpsrad", 0, 1);
    addOperandSwapTerm(*fl, "vpor", 0, 1);
    addOperandSwapTerm(*fl, "vpxor", 0, 1);
    addOperandSwapTerm(*fl, "vpab", 0, 1);
    addOperandSwapTerm(*fl, "vpadd", 0, 1);
    addOperandSwapTerm(*fl, "vphadd", 0, 1);
    addOperandSwapTerm(*fl, "vpsub", 0, 1);
    addOperandSwapTerm(*fl, "vpmin", 0, 1);
    addOperandSwapTerm(*fl, "vpmax", 0, 1);
    addOperandSwapTerm(*fl, "vpmov", 0, 1);
    addOperandSwapTerm(*fl, "vpavg", 0, 1);
    //addOperandSwapTerm(*fl, "vpcmp", 0, 1);
    addOperandSwapTerm(*fl, "vpsra", 0, 1);
    addOperandSwapTerm(*fl, "vpsrld", 0, 1);
    addOperandSwapTerm(*fl, "vmask", 0, 1);
    addOperandSwapTerm(*fl, "vexp", 0, 1);
    addOperandSwapTerm(*fl, "vrcp", 0, 1);
    addOperandSwapTerm(*fl, "cmpps", 0, 1);
    addOperandSwapTerm(*fl, "valign", 0, 2);
    addOperandSwapTerm(*fl, "vgather", 0, 2);
    //addOperandSwapTerm(*fl, "vinsert", 0, 2);
    //addOperandSwapTerm(*fl, "vfixup", 0, 2);
    addOperandSwapTerm(*fl, "vfixup", 0, 1);
    addOperandSwapTerm(*fl, "vshuff", 0, 2);
    addOperandSwapTerm(*fl, "vptern", 0, 2);
    addOperandSwapTerm(*fl, "vpalign", 0, 2);
    addOperandSwapTerm(*fl, "vgetman", 0, 2);
    addOperandSwapTerm(*fl, "vreduce", 0, 2);
    addOperandSwapTerm(*fl, "vrnd", 0, 2);
    addOperandSwapTerm(*fl, "vdbp", 0, 2);
    //addOperandSwapTerm(*fl, "vrange", 0, 2);
    addOperandSwapTerm(*fl, "vrange", 0, 1);
    return fl;
}

void swapEnterOperands(char* buf, int bufLen) {
    static FindList* fl = initSwapEnterOperandsFindList();
    fl->process(buf, bufLen);
}

FindList* initDyninstMnemonicsFindList() {
    FindList* fl = new FindList(877);
    //addReplaceTerm(*fl, "bq ", "b ");
    addReplaceTerm(*fl, "{%k0}", "");
    addReplaceTerm(*fl, "pminsl ", "pminsd ");
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

   InstructionDecoder d = InstructionDecoder(inst, nBytes, Arch_x86_64);
   Instruction::Ptr p = d.decode();
   InstructionAPI::Instruction* insn_ptr = p.get();
   assert(insn_ptr);

   strncpy(buf, insn_ptr->format().c_str(), bufLen);
   return 0;
}
