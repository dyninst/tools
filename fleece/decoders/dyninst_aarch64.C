
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

#include <assert.h>
#include "Decoder.h"
#include "InstructionDecoder.h"
#include "Normalization.h"
#include "StringUtils.h"

using namespace Dyninst;
using namespace InstructionAPI;

int dyninst_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {

    if (nBytes <= 0) {
        return -1;
    }
   
    if (isAarch64SysRegInsn(inst, nBytes, buf, bufLen)) {
        return 0;
    }
   
    InstructionDecoder d(inst, nBytes, Arch_aarch64);
    Instruction::Ptr p = d.decode();
    strncpy(buf, p->format().c_str(), bufLen);

    return 0;
}

void replacePlusWithComma(char* buf, int bufLen) {
    std::string result(buf);
    size_t index = result.find(" + ");
    if (index != std::string::npos) {
        result.replace(index, 3, ", ");
    }
    strncpy(buf, result.c_str(), bufLen);
}

/*
 * Adds an implicit zero immediate to the end of integer and float compare instructions.
 * Example use cases:
 *
 * Changes: cmlt d6, d25
 * To:      cmlt d6, d25, #0
 *
 * Opcode variations are: cmlt, cmle, cmgt, cmge, fcmlt, fcmle, fcmgt, fcmge
 */
void addImplicitZeroOperandToCompareInsns(char* buf, int bufLen) {
    char* cur = buf;

    // Advance past a leading 'f' if there is one, so that floating point and integer
    // variants can be treated identically.
    if (*cur == 'f') {
        ++cur;
    }

    // Compare three letters of the opcode to see if this is a compare instruction that
    // should be normalized by this rule.
    if (!strncmp(cur, "cml", 3) || !strncmp(cur, "cmg", 3)) {

        // Check the number of operands by counting the number of commas. If we count
        // only one comma in the string, then we have a 2-operand compare, and we should
        // append ", #0".

        // Seek to the end of the current mnemonic, counting commas.
        int nCommas = 0;
        while (*cur) {
            if (*cur == ',') {
                ++nCommas;
            }
            ++cur;
        }

        if (nCommas == 1) {
            
            // We have a two-operand version, so append ", #0"
            strncpy(cur, ", #0", bufLen - (cur - buf));
        }
    }
}

void decShiftConstants(char* buf, int bufLen) {
    std::string result(buf);
    size_t index = result.find("lsl");
    if (index != std::string::npos) {
        if (buf[index + 3] == ' ' && buf[index + 4] == '0') {
            hexToDecConstants(buf + index, bufLen - index);
            char tmp[bufLen];
            strncpy(tmp, buf + index + 4, bufLen - index - 4);
            snprintf(buf + index, bufLen - index, "lsl #%s", tmp);
        }
    }
}

void addCommaToOperandShifts(char* buf, int bufLen) {
    std::string result(buf);
    size_t index = result.find(" ror ");
    if (index != std::string::npos) {
        result.replace(index, 5, ", ror ");
    }
    index = result.find(" lsr ");
    if (index != std::string::npos) {
        result.replace(index, 5, ", lsr ");
    }
    index = result.find(" asr ");
    if (index != std::string::npos) {
        result.replace(index, 5, ", asr ");
    }
    strncpy(buf, result.c_str(), bufLen);
}

/*
* Creates a FindList object that will remove a trailing '2' from a list of
* opcodes.
*/
FindList* initRemoveUnnecessaryOpcode2FindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, "mul2 ", "mul ");
    addReplaceTerm(*fl, "fmla2 ", "fmla ");
    addReplaceTerm(*fl, "fmls2 ", "fmls ");
    addReplaceTerm(*fl, "fmulx2 ", "fmulx ");
    addReplaceTerm(*fl, "rev162 ", "rev16 ");
    addReplaceTerm(*fl, "rev322 ", "rev32 ");
    addReplaceTerm(*fl, "rev642 ", "rev64 ");
    addReplaceTerm(*fl, "sqneg2 ", "sqneg ");
    addReplaceTerm(*fl, "usqadd2 ", "usqadd ");
    addReplaceTerm(*fl, "suqadd2 ", "suqadd ");
    addReplaceTerm(*fl, "sqabs2 ", "sqabs ");
    addReplaceTerm(*fl, "sqrdmulh2 ", "sqrdmulh ");
    return fl;
}

/*
* Remove a trailing '2' from a list of opcodes provided in the intialization
* code for the FindList used by this function.
*/
void removeUnnecessaryOpcode2(char* buf, int bufLen) {
    static FindList* fl = initRemoveUnnecessaryOpcode2FindList();
    fl->process(buf, bufLen);
}

FindList* initRemoveImplicitOperandsFindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, " pc +", "");
    addReplaceTerm(*fl, ", pc", "");
    addReplaceTerm(*fl, ", pstate", "");
    addReplaceTerm(*fl, "pstate", "");
    return fl;
}

void removeImplicitOperands(char* buf, int bufLen) {
    static FindList* fl = initRemoveImplicitOperandsFindList();
    fl->process(buf, bufLen);
}

void fixSIMDMemOperands(char* buf, int bufLen) {
    if (strncmp(buf, "ld", 2) && strncmp(buf, "st", 2)) {
        return;
    }
    char middle[bufLen];
    char* midPlace = &(middle[0]);
    char ending[bufLen];
    char* cur = buf;
    int nWays = *(buf + 2) - 48;
    if (nWays < 1 || nWays > 4) {
        return;
    }

    while (*cur && !isspace(*cur)) {
        ++cur;
    }
    if (!*cur) {
        return;
    }
    char* start = cur + 1;

    int commasSeen = 0;
    while (*cur) {
        if (*cur == ',') {
            ++commasSeen;
        }
        ++cur;
    }
    bool removeLast = true;
    int nOperands = commasSeen - 2;
    if (*(cur - 1) == ']') {
        removeLast = false;
        nOperands = commasSeen;
    }
    cur = start;
    
    commasSeen = 0;
    while (*cur && commasSeen < nOperands) {
        *midPlace = *cur;
        ++midPlace;
        if (*cur == ',') {
            ++commasSeen;
        }
        ++cur;
    }
    
    if (!*cur) {
        return;
    }

    --midPlace;
    *midPlace = '\0';

    char* startOfEndStr = cur;
    if (removeLast) {
        while (*cur && commasSeen < nOperands) {
            if (*cur == ',') {
                ++commasSeen;
                if (commasSeen == nOperands + 2) {
                    *cur = '\0';
                }
            }
            ++cur;
        }
    }

    strcpy(ending, startOfEndStr);
    snprintf(start, bufLen - (start - buf), "{%s},%s", middle, ending);
    if (removeLast) {
        cur = buf;
        while (*cur) {
            ++cur;
        }
        while (*cur != ',' && cur > buf) {
            --cur;
        }
        if (*cur == ',') {
            *cur = '\0';
        }
    }
}

void removeTrailingBranchComma(char* buf, int bufLen) {
    char* cur = buf;
    if (strncmp(buf, "b.", 2)) {
        return;
    }
    while (*cur) {
        ++cur;
    }
    cur -= 2;
    if (!strncmp(cur, ", ", 2)) {
        *cur = '\0';
    }
}

void dyninst_aarch64_norm(char* buf, int bufLen) {
    toLowerCase(buf, bufLen);
    fixSIMDMemOperands(buf, bufLen);
    removeImplicitOperands(buf, bufLen);
    addCommaToOperandShifts(buf, bufLen);
    replacePlusWithComma(buf, bufLen);
    decShiftConstants(buf, bufLen);
    addImplicitZeroOperandToCompareInsns(buf, bufLen);
    removeUnnecessaryOpcode2(buf, bufLen);
    removeTrailingBranchComma(buf, bufLen);
}

int dyninst_aarch64_init(void) {
    return 0;
}
