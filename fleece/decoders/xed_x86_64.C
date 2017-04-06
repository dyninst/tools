
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

#ifdef __cplusplus
extern "C" {
#include "xed-interface.h"
}
#else
#include "xed-interface.h"
#endif

#include <iomanip>
#include <iostream>
#include "Normalization.h"
#include "StringUtils.h"

#define XED_MACHINE_MODE XED_MACHINE_MODE_LONG_64
#define XED_ADDRESS_WIDTH XED_ADDRESS_WIDTH_64b


int xedInit(void) {
   xed_tables_init();
   return 0;
}

void fixMmxRegs(char* buf, int bufLen) {

    // We are looking for the 'x' in 'mmx', so the string must be at least 3
    // letters, and we can skip the first two.
    if (*buf == '\0' || *(buf + 1) == '\0') {
        return;
    }
    
    char* cur = buf + 2;
    char* place = buf + 2;
    
    while (*cur) {
        if (*cur != 'x' || *(cur - 1) != 'm' || *(cur - 2) != 'm') {
            *place = *cur;
            place++;
        }
        cur++;
    }
    *place = '\0';
}

void fixVexMaskOperations(char* buf, int bufLen) {
    
    // Start at the beginning of the buffer and go to the end.
    char* cur = buf;
    while (*cur) {
        cur++;
    }

    // If the last character isn't a bracket, we aren't interested in this
    // insn, so return.
    if (*(cur - 1) != '}') {
        return;
    }

    // We will need to increase the length of the instruction by two, so make
    // sure we have room for that.
    char* insnEnd = cur - 1;
    if (buf + bufLen <= insnEnd + 2) {
        std::cerr << "ERROR: Decoding buffer too short!\n";
        exit(-1);
    }

    // Go back until we identify an opening brace.
    while (cur >= buf && *cur != '{') {
        cur--;
    }

    // Vector operations all begin with 'r' or 's'. If this braced value
    // doesn't, return.
    if (*(cur + 1) != 'r' && *(cur + 1) != 's') {
        return;
    }

    // We now know that were dealing with a vector operation. Record its length
    // and allocate a buffer to hold it.
    int opLen = strlen(cur);
    char tmpBuf[opLen + 1];
    char* tmp = &tmpBuf[0];
    strcpy(tmp, cur);

    // Start at the beginning of the instruction and find the first space,
    // which is where we want to place the vector operation.
    cur = buf;
    while (*cur && *cur != ' ') {
        cur++;
    }

    // If we didn't find a space, return.
    if (*cur != ' ') {
        return;
    }
    
    // We want to copy this before the first %*mm# register. There may be a single operand
    // before that register, so copy over and see.
    if (*(cur + 3) != 'm' || *(cur + 4) != 'm') {
        ++cur;
        while (*cur && *cur != ' ') {
            ++cur;
        }
    }

    // Verify that we found another place for the mask, or return.
    if (*cur != ' ') {
        return;
    }

    // Record the position to copy the operation to.
    char* opPos = cur + 1;
    int copyOffset = opLen + 2;

    // Copy the instruction starting at the end.
    cur = insnEnd + 2; // include space for the ", "
    *(cur + 1) = 0;
    while (cur >= opPos + copyOffset) {
        *cur = *(cur - copyOffset);
        cur--;
    }

    // We've now copied all of the instruction leaving space for the operation
    // and ", ", so add those in.
    strncpy(opPos, tmp, opLen);
    *(opPos + opLen) = ',';
    *(opPos + opLen + 1) = ' ';
}

void fixVexTrailingX(char* buf, int bufLen) {
    char* cur = buf;
    
    while (*cur && !((cur == buf || *(cur - 1) == ' ') && 
            *cur == 'v' /*&& *(cur + 2) == 'p'*/)) {
        cur++;
    }

    if (!*cur) {
        return;
    }

    while (*cur && *cur != ' ') {
        cur++;
    }

    if (*(cur - 1) == 'x') {
        while (*cur) {
            *(cur - 1) = *cur;
            cur++;
        }
        *(cur - 1) = '\0';
    }
}

FindList* initOpcodeDressingFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "bq ", "b ");
    addReplaceTerm(*fl, "by ", "b ");
    addReplaceTerm(*fl, "bz ", "b ");
    addReplaceTerm(*fl, "wl ", "w ");
    addReplaceTerm(*fl, "wq ", "w ");
    addReplaceTerm(*fl, "wy ", "w ");
    addReplaceTerm(*fl, "wz ", "w ");
    addReplaceTerm(*fl, "sdl ", "sd ");
    addReplaceTerm(*fl, "dq ", "d ");
    addReplaceTerm(*fl, "dy ", "d ");
    addReplaceTerm(*fl, "dz ", "d ");
    addReplaceTerm(*fl, "qq ", "q ");
    addReplaceTerm(*fl, "qz ", "q ");
    addReplaceTerm(*fl, "sdl ", "sl ");
    addReplaceTerm(*fl, "psq ", "ps ");
    addReplaceTerm(*fl, "psx ", "ps ");
    addReplaceTerm(*fl, "psy ", "ps ");
    addReplaceTerm(*fl, "pdz ", "pd ");
    addReplaceTerm(*fl, "prefetchz ", "prefetch ");
    addReplaceTerm(*fl, "cflushz ", "cflush ");
    addReplaceTerm(*fl, "sww", "sw");
    addReplaceTerm(*fl, "sxd ", "slq ");
    addReplaceTerm(*fl, "iretd", "iretl");
    return fl;
}

void fixExtraOpcodeDressing(char* buf, int bufLen) {
    static FindList* fl = initOpcodeDressingFindList();

    fl->process(buf, bufLen);

    // Need to verify that the below are necessary.
    /*
    replaceStr(buf, bufLen, "swx ", "swx ");
    replaceStr(buf, bufLen, "bwx ", "bwx ");
    replaceStr(buf, bufLen, "ubx ", "ub ");
    replaceStr(buf, bufLen, "bdx ", "bd ");
    replaceStr(buf, bufLen, "uby ", "ub ");
    replaceStr(buf, bufLen, "pdx ", "pd ");
    replaceStr(buf, bufLen, "qdx ", "qd ");
    replaceStr(buf, bufLen, "sbx ", "sb ");
    replaceStr(buf, bufLen, "dnx ", "dn ");
    replaceStr(buf, bufLen, "orx ", "or ");
    replaceStr(buf, bufLen, "ldx ", "ld ");
    replaceStr(buf, bufLen, "dqx ", "dq ");
    replaceStr(buf, bufLen, "bbx ", "bb ");
    replaceStr(buf, bufLen, "bqx ", "bq ");
    replaceStr(buf, bufLen, "ddy ", "dd ");
    */
}

void removeImplicitST0(char* buf, int bufLen) {
    
    std::string str = std::string(buf);
    
    if (*buf != 'f' && str.find(" f") == std::string::npos) {
        return;
    }

    removeOperand(str, "fadd", ", %st(0)");
    removeOperand(str, "fld", ", %st(0)");
    removeOperand(str, "fbld", ", %st(0)");
    removeOperand(str, "fst", "%st(0), ");
    removeOperand(str, "fbstp", "%st(0), ");
    removeOperand(str, "fstpq", "%st(0), ");
    //removeOperand(str, "fcmov", ", %st(0)"); // x
    removeOperand(str, "fild", ", %st(0)");
    removeOperand(str, "fist", "%st(0), ");
    removeOperand(str, "fisub", ", %st(0)");
    removeOperand(str, "fsub", ", %st(0)");
 
    removeOperand(str, "fmul", ", %st(0)");
    removeOperand(str, "fucom", ", %st(0)");
    removeOperand(str, "fcom", ", %st(0)");
    removeOperand(str, "fidiv", ", %st(0)");
    removeOperand(str, "fdiv", ", %st(0)");
    removeOperand(str, "fimul", ", %st(0)");
    removeOperand(str, "fiadd", ", %st(0)");
 
    removeOperand(str, "ficom", ", %st(0)");
    removeOperand(str, "fsubrl", "%st(0), ");
    removeOperand(str, "fbstp", "%st(0), ");
    removeOperand(str, "fsqrt", " %st(0)");
    removeOperand(str, "fxch", ", %st(0)");
    removeOperand(str, "fptan", ", %st(0)");
 
    removeOperand(str, "fprem1", "%st(1), %st(0)");
    removeOperand(str, "fprem", "%st(1), %st(0)");
    removeOperand(str, "fscale", "%st(1), %st(0)");
    removeOperand(str, "fxtract", "%st(1), %st(0)");
    removeOperand(str, "fpatan", "%st(1), %st(0)");
    removeOperand(str, "fsincos", "%st(1), %st(0)");
    removeOperand(str, "fchs", "%st(0)");
    removeOperand(str, "fldz", "%st(0)");
    removeOperand(str, "fldpi", "%st(0)");
    removeOperand(str, "ftst", "%st(0)");
    removeOperand(str, "fcompp", "%st(1)");
    removeOperand(str, "fucompp", "%st(1)");
    removeOperand(str, "fptan", "%st(1)");
    removeOperand(str, "fld1", "%st(0)");
    removeOperand(str, "fsin", "%st(0)");
    removeOperand(str, "fabs", "%st(0)");
    removeOperand(str, "fcos", "%st(0)");
    removeOperand(str, "frndint", "%st(0)");
    removeOperand(str, "fdld2t", "%st(0)");
    removeOperand(str, "fxam", "%st(0)");
    removeOperand(str, "fdln2", "%st(0)");
    removeOperand(str, "fldlg2", "%st(0)");
    removeOperand(str, "fldln2", "%st(0)");
    removeOperand(str, "fldl2e", "%st(0)");
    removeOperand(str, "fldl2t", "%st(0)");
    removeOperand(str, "fyl2xp1", "%st(1), %st(0)");
    removeOperand(str, "fyl2x", "%st(1), %st(0)");
    removeOperand(str, "f2xm1", "%st(1), %st(0)");
    removeOperand(str, "f2xm1", "%st(0)");
    
    strncpy(buf, str.c_str(), bufLen);
    if (buf[str.length() - 1] == ' ') {
       buf[str.length() - 1] = 0;
    }
}

void removeExtraAddr32(char* buf, int bufLen) {
    std::string str = std::string(buf);
    
    if (str.find("addr32 j") == std::string::npos) {
        return;
    }
   
    removeOperand(str, "", "addr32");

    strncpy(buf, str.c_str(), bufLen);
    if (buf[str.length() - 1] == ' ') {
       buf[str.length() - 1] = 0;
    }
}

void removeExtraData16(char* buf, int bufLen) {
    std::string str = std::string(buf);
    
    if (str.find("data16") == std::string::npos) {
        return;
    }
   
    removeOperand(str, "pushfw", "data16");
    removeOperand(str, "popfw", "data16");
    removeOperand(str, "cbw", "data16");
    removeOperand(str, "cwd", "data16");
    removeOperand(str, "leavew", "data16");

    strncpy(buf, str.c_str(), bufLen);
    if (buf[str.length() - 1] == ' ') {
       buf[str.length() - 1] = 0;
    }
}

void xed_x86_64_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    fixStRegs(buf, bufLen);
    fixMmxRegs(buf, bufLen);
    fixExtraOpcodeDressing(buf, bufLen);
    fixVexTrailingX(buf, bufLen);
    fixVexMaskOperations(buf, bufLen);
    removeImplicitST0(buf, bufLen);
    cleanX86NOP(buf, bufLen);
    removeExtraData16(buf, bufLen);
    removeExtraAddr32(buf, bufLen);
}

int xed_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH;

    xed_error_enum_t err;
    xed_decoded_inst_t decoded_inst;

    xed_decoded_inst_zero(&decoded_inst);
    xed_decoded_inst_set_mode(&decoded_inst, mmode, stack_addr_width);
    err = xed_decode(&decoded_inst, (xed_uint8_t*)inst, nBytes);
    if (err != XED_ERROR_NONE) {
        return -1;
    }
    if (!xed_format_context(XED_SYNTAX_ATT, 
            &decoded_inst, buf, bufLen, 0, 0, 0)) {
        return -1;
    }
    return 0;
}

