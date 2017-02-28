
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

void fixStRegs(char* buf, int bufLen) {
    char tmpBuf[bufLen];
    char* place = &tmpBuf[0];
    char* cur = buf;
    char* firstRegStart = NULL;
    while (*cur && place + 5 < &tmpBuf[bufLen - 1]) {
        if (!strncmp(cur, "%st", 3)) {
            if (firstRegStart == NULL) {
                firstRegStart = cur;
            }
            for (int i = 0; i < 3; i++) {
                *place = *cur;
                place++;
                cur++;
            }
            *place = '(';
            place++;
            *place = *cur;
            place++;
            *place = ')';
            place++;
        } else if (firstRegStart != NULL) {
            *place = *cur;
            place++;
        }
        cur++;
    }
    *place = '\0';
    if (firstRegStart != NULL) {
        strncpy(firstRegStart, &tmpBuf[0], bufLen + buf - firstRegStart);
    }
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

void fixExtraOpcodeDressing(char* buf, int bufLen) {
    if (strstr(buf, "sd") != NULL) {
        replaceStr(buf, bufLen, "sdl ", "sl ");
    }
    if (strstr(buf, "ps") != NULL) {
        replaceStr(buf, bufLen, "psq ", "ps ");
        replaceStr(buf, bufLen, "psx ", "ps ");
        replaceStr(buf, bufLen, "psy ", "ps ");
    }
    if (strstr(buf, "pd") != NULL) {
        replaceStr(buf, bufLen, "pdz ", "pd ");
    }
    if (strstr(buf, "prefetch") != NULL) {
        replaceStr(buf, bufLen, "z ", " ");
    } else if (strstr(buf, "cflush") != NULL) {
        replaceStr(buf, bufLen, "z ", " ");
    }
  
    replaceStr(buf, bufLen, "bq ", "b ");
    replaceStr(buf, bufLen, "by ", "b ");
    replaceStr(buf, bufLen, "bz ", "b ");
    replaceStr(buf, bufLen, "wl ", "w ");
    replaceStr(buf, bufLen, "wq ", "w ");
    replaceStr(buf, bufLen, "wy ", "w ");
    replaceStr(buf, bufLen, "wz ", "w ");
    replaceStr(buf, bufLen, "dl ", "d ");
    replaceStr(buf, bufLen, "dq ", "d ");
    replaceStr(buf, bufLen, "dy ", "d ");
    replaceStr(buf, bufLen, "dz ", "d ");
    replaceStr(buf, bufLen, "qq ", "q ");
    replaceStr(buf, bufLen, "qz ", "q ");

    replaceStr(buf, bufLen, "sww", "sw");
    replaceStr(buf, bufLen, "sxd ", "slq ");
    replaceStr(buf, bufLen, "iretd", "iretl");

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
   removeOperand(str, "fldl2e", "%st(0)");
   removeOperand(str, "fyl2xp1", "%st(1), %st(0)");
   removeOperand(str, "fyl2x", "%st(1), %st(0)");
   removeOperand(str, "f2xm1", "%st(1), %st(0)");
   
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

