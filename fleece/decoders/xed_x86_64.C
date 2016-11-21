
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
#include "Alias.h"
#include "Normalization.h"
#include "StringUtils.h"

#define XED_MACHINE_MODE XED_MACHINE_MODE_LONG_64
#define XED_ADDRESS_WIDTH XED_ADDRESS_WIDTH_64b

void aliasSizes(const char* base) {
   int baseLen = strlen(base);
   char* withSize = (char*)malloc(baseLen + 2);
   strcpy(withSize, base);
   withSize[baseLen + 1] = 0;

   
   withSize[baseLen] = 'w';
   Alias::addAlias(withSize, base);

   withSize[baseLen] = 'l';
   Alias::addAlias(withSize, base);
   
   withSize[baseLen] = 'b';
   Alias::addAlias(withSize, base);

   withSize[baseLen] = 'q';
   Alias::addAlias(withSize, base);

   free(withSize);
}

int xedInit(void) {
   xed_tables_init(); 

   Alias::addAlias("%mmx0", "%mm0");
   Alias::addAlias("%mmx1", "%mm1");
   Alias::addAlias("%mmx2", "%mm2");
   Alias::addAlias("%mmx3", "%mm3");
   Alias::addAlias("%mmx4", "%mm4");
   Alias::addAlias("%mmx5", "%mm5");
   Alias::addAlias("%mmx6", "%mm6");
   Alias::addAlias("%mmx7", "%mm7");

   Alias::addAlias("%mmx0,", "%mm0,");
   Alias::addAlias("%mmx1,", "%mm1,");
   Alias::addAlias("%mmx2,", "%mm2,");
   Alias::addAlias("%mmx3,", "%mm3,");
   Alias::addAlias("%mmx4,", "%mm4,");
   Alias::addAlias("%mmx5,", "%mm5,");
   Alias::addAlias("%mmx6,", "%mm6,");
   Alias::addAlias("%mmx7,", "%mm7,");
   
   aliasSizes("or");
   aliasSizes("adc");
   aliasSizes("sub");
   aliasSizes("and");
   aliasSizes("xor");
   aliasSizes("lea");
   aliasSizes("lar");
   aliasSizes("mov");
   aliasSizes("add");
   aliasSizes("sbb");
   aliasSizes("cmp");
   aliasSizes("str");
   aliasSizes("pop");
   aliasSizes("push");
   aliasSizes("shrd");
   aliasSizes("xchg");
   aliasSizes("imul");
   aliasSizes("setb");
   aliasSizes("sets");
   aliasSizes("pand");
   aliasSizes("test");
   aliasSizes("seto");
   aliasSizes("cmovl");
   aliasSizes("cmovo");
   aliasSizes("cmovp");
   aliasSizes("fimul");
   aliasSizes("paddw");
   aliasSizes("pslld");
   aliasSizes("psllq");
   aliasSizes("pandn");
   aliasSizes("psadbw");
   aliasSizes("paddsw");
   aliasSizes("pmulhw");
   aliasSizes("pminsw");
   aliasSizes("pmaxsw");
   aliasSizes("pmulhuw");
   aliasSizes("pcmpgtd");
   aliasSizes("pcmpgtb");
   aliasSizes("ucomiss");
   aliasSizes("punpckldq");
   aliasSizes("packssdwq");
   aliasSizes("punpckhwd");

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
    while (cur > opPos + copyOffset) {
        *cur = *(cur - copyOffset);
        cur--;
    }

    // We've now copied all of the instruction leaving space for the operation
    // and ", ", so add those in.
    strncpy(opPos, tmp, opLen);
    *(opPos + opLen) = ',';
    *(opPos + opLen + 1) = ' ';
}

void fixExtraOpcodeDressing(char* buf, int bufLen) {
    replaceStr(buf, bufLen, "sdq ", "sd ");
    replaceStr(buf, bufLen, "sdl ", "sl ");
    replaceStr(buf, bufLen, "psq ", "ps ");
    replaceStr(buf, bufLen, "fqq", "fq");
    replaceStr(buf, bufLen, "insbb", "insb");
    replaceStr(buf, bufLen, "wdy ", "wd ");
    replaceStr(buf, bufLen, "psx ", "ps ");
    replaceStr(buf, bufLen, "sqq ", "sq ");
    replaceStr(buf, bufLen, "psy ", "ps ");
    replaceStr(buf, bufLen, "pdy ", "pd ");
    replaceStr(buf, bufLen, "sxd ", "slq ");
    replaceStr(buf, bufLen, "iretd", "iretl");
}

void removeImplicitST0(char* buf, int bufLen) {
    
   std::string str(buf);
  
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
    fixVexMaskOperations(buf, bufLen);
    removeImplicitST0(buf, bufLen);

   /*trimHexZeroes(buf, bufLen);
   trimHexFs(buf, bufLen);

   std::string str(buf);
  
   removeOperand(str, "fadd", ", %st0");
   removeOperand(str, "faddb", ", %st0");
   removeOperand(str, "faddw", ", %st0");
   removeOperand(str, "faddl", ", %st0");
   removeOperand(str, "faddq", ", %st0");

   removeOperand(str, "fldl", ", %st0");
   removeOperand(str, "fldq", ", %st0");
   removeOperand(str, "fld", ", %st0");
   removeOperand(str, "fbld", ", %st0");
   removeOperand(str, "fst", "%st0, ");
   removeOperand(str, "fstp", "%st0, ");
   removeOperand(str, "fstpl", "%st0, ");
   removeOperand(str, "fbstp", "%st0, ");
   removeOperand(str, "fstpq", "%st0, ");
   removeOperand(str, "fcmovu", ", %st0");
   removeOperand(str, "fcmovnu", ", %st0");
   removeOperand(str, "fildw", ", %st0");
   removeOperand(str, "fildq", ", %st0");
   removeOperand(str, "fistw", "%st0, ");
   removeOperand(str, "fistpl", "%st0, ");
   removeOperand(str, "fistpq", "%st0, ");
   removeOperand(str, "fistpw", "%st0, ");
   removeOperand(str, "fisttpw", "%st0, ");
   removeOperand(str, "fisubw", ", %st0");
   removeOperand(str, "fisubl", ", %st0");
   removeOperand(str, "fsubq", ", %st0");
   removeOperand(str, "fsubrq", ", %st0");
   removeOperand(str, "fsubl", ", %st0");

   removeOperand(str, "fmull", ", %st0");
   removeOperand(str, "fucom", ", %st0");
   removeOperand(str, "fcom", ", %st0");
   removeOperand(str, "fcomp", ", %st0");
   removeOperand(str, "fcoml", ", %st0");
   removeOperand(str, "fcompl", ", %st0");
   removeOperand(str, "fidivw", ", %st0");
   removeOperand(str, "fdivl", ", %st0");
   removeOperand(str, "fdivrl", ", %st0");
   removeOperand(str, "fsubrl", ", %st0");
   removeOperand(str, "fisubrw", ", %st0");
   removeOperand(str, "fisubrl", ", %st0");
   removeOperand(str, "fidivrw", ", %st0");
   removeOperand(str, "fidivrl", ", %st0");
   removeOperand(str, "ficomw", ", %st0");
   removeOperand(str, "ficompw", ", %st0");
   removeOperand(str, "ficomu", ", %st0");
   removeOperand(str, "ficoml", ", %st0");
   removeOperand(str, "ficompl", ", %st0");
   removeOperand(str, "ficompw", ", %st0");
   removeOperand(str, "fimulw", ", %st0");
   removeOperand(str, "fimull", ", %st0");
   removeOperand(str, "fiaddl", ", %st0");

   removeOperand(str, "fcoml", "%st0, ");
   removeOperand(str, "ficoml", "%st0, ");
   removeOperand(str, "fmull", "%st0, ");
   removeOperand(str, "fimull", "%st0, ");
   removeOperand(str, "fiaddl", "%st0, ");
   removeOperand(str, "fistl", ", %st0");
   removeOperand(str, "fstl", ", %st0");
   removeOperand(str, "fstpl", ", %st0");
   removeOperand(str, "fldl", "%st0, ");
   removeOperand(str, "fbldl", "%st0, ");
   removeOperand(str, "fildl", "%st0, ");
   removeOperand(str, "fsubrl", "%st0, ");
   removeOperand(str, "fsubrwl", ", %st0");
   removeOperand(str, "fisubl", "%st0, ");
   removeOperand(str, "fbstpl", "%st0, ");
   removeOperand(str, "fisttpl", "%st0, ");
   removeOperand(str, "fsqrtl", " %st0");
   
   strncpy(buf, str.c_str(), bufLen);
   if (buf[str.length() - 1] == ' ') {
      buf[str.length() - 1] = 0;
   }
   */
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

