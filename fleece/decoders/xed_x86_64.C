
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

    if (*(cur - 1) == 'x' || *(cur - 1) == 'z') {
        while (*cur) {
            *(cur - 1) = *cur;
            cur++;
        }
        *(cur - 1) = '\0';
    }
}

void fixPFInsnSuffix(char* buf, int bufLen) {
    char* cur = buf;
    bool done = false;
    while (!done && *cur) {
        if (!strncmp(cur, "pf", 2)) {
            done = true;
            while (*cur && *cur != ' ') {
                ++cur;
            }
            *(cur - 1) = ' ';
        }
        while (*cur && !isspace(*cur)) {
            ++cur;
        }
        if (*cur) {
            ++cur;
        }
    }
}

void fixPrefetchSuffix(char* buf, int bufLen) {
    char* cur = buf;
    bool done = false;
    while (!done && *cur) {
        if (!strncmp(cur, "prefetch", 8)) {
            done = true;
            while (*cur && *cur != ' ') {
                ++cur;
            }
            *(cur - 1) = ' ';
        }
        while (*cur && !isspace(*cur)) {
            ++cur;
        }
        if (*cur) {
            ++cur;
        }
    }
}

FindList* initMaskNameFindList() {
    FindList* fl = new FindList(409);
    //addReplaceTerm(*fl, "bq ", "b ");
    addReplaceTerm(*fl, "rne-sae", "rn-sae");
    return fl;
}

void fixMaskName(char* buf, int bufLen) {
    static FindList* fl = initMaskNameFindList();
    fl->process(buf, bufLen);
}

FindList* initConvertFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "ssq ", "ss ");
    addReplaceTerm(*fl, "ssl ", "ss ");
    addReplaceTerm(*fl, "sdl ", "sd ");
    addReplaceTerm(*fl, "pdq ", "pd ");
    return fl;
}

FindList* initNonConvertFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "y ", " ");
    addReplaceTerm(*fl, "x ", " ");
    return fl;
}

FindList* initNonVecFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "pxorx", "pxor");
    addReplaceTerm(*fl, "porx", "por");
    addReplaceTerm(*fl, "pxorq", "pxor");
    addReplaceTerm(*fl, "porq", "por");
    return fl;
}

FindList* initPInsnSuffixFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "bq ", "b ");
    addReplaceTerm(*fl, "dq ", "d ");
    addReplaceTerm(*fl, "nq ", "n ");
    addReplaceTerm(*fl, "pq ", "p ");
    return fl;
}


FindList* initStrInsnDressingFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "stosll", "stosl");
    addReplaceTerm(*fl, "movsll", "movsl");
    addReplaceTerm(*fl, "scasll", "scasl");
    addReplaceTerm(*fl, "insll", "insl");
    addReplaceTerm(*fl, "outsll", "outsl");
    addReplaceTerm(*fl, "lodsll", "lodsl");
    addReplaceTerm(*fl, "cmpsll", "cmpsl");
    return fl;
}

FindList* initOpcodeDressingFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "bx ", "b ");
    addReplaceTerm(*fl, "wx ", "w ");
    addReplaceTerm(*fl, "dx ", "d ");
    addReplaceTerm(*fl, "qx ", "q ");
    addReplaceTerm(*fl, "by ", "b ");
    addReplaceTerm(*fl, "bz ", "b ");
    addReplaceTerm(*fl, "wl ", "w ");
    addReplaceTerm(*fl, "wq ", "w ");
    addReplaceTerm(*fl, "wy ", "w ");
    addReplaceTerm(*fl, "wz ", "w ");
    addReplaceTerm(*fl, "ww ", "w ");
    addReplaceTerm(*fl, "sdl ", "sd ");
    //addReplaceTerm(*fl, "dq ", "d ");
    //addReplaceTerm(*fl, "dl ", "d ");
    addReplaceTerm(*fl, "dy ", "d ");
    addReplaceTerm(*fl, "dz ", "d ");
    addReplaceTerm(*fl, "qq ", "q ");
    addReplaceTerm(*fl, "qql ", "qq ");
    addReplaceTerm(*fl, "pdq ", "pd ");
    //addReplaceTerm(*fl, "ddq ", "dd ");
    addReplaceTerm(*fl, "sdq ", "sd ");
    addReplaceTerm(*fl, "sbq ", "sb ");
    addReplaceTerm(*fl, "dbq ", "db ");
    addReplaceTerm(*fl, "wdq ", "wd ");
    addReplaceTerm(*fl, "qz ", "q ");
    addReplaceTerm(*fl, "rdl ", "rd ");
    addReplaceTerm(*fl, "ldl ", "ld ");
    addReplaceTerm(*fl, "ldq ", "ld ");
    addReplaceTerm(*fl, "dql ", "dq ");
    addReplaceTerm(*fl, "wdl ", "wd ");
    addReplaceTerm(*fl, "sdl ", "sl ");
    addReplaceTerm(*fl, "fdl ", "fd ");
    addReplaceTerm(*fl, "pdl ", "pd ");
    addReplaceTerm(*fl, "ndl ", "nd ");
    addReplaceTerm(*fl, "bdl ", "bd ");
    addReplaceTerm(*fl, "wql ", "wq ");
    addReplaceTerm(*fl, "siq ", "si ");
    addReplaceTerm(*fl, "sil ", "si ");
    addReplaceTerm(*fl, "piq ", "pi ");
    addReplaceTerm(*fl, "psq ", "ps ");
    addReplaceTerm(*fl, "psx ", "ps ");
    addReplaceTerm(*fl, "psy ", "ps ");
    addReplaceTerm(*fl, "psl ", "ps ");
    addReplaceTerm(*fl, "pdz ", "pd ");
    addReplaceTerm(*fl, "nrq ", "nr ");
    addReplaceTerm(*fl, "bqw ", "bq ");
    addReplaceTerm(*fl, "sww", "sw");
    addReplaceTerm(*fl, "ssl", "ss");
    addReplaceTerm(*fl, "ddl", "dd");
    addReplaceTerm(*fl, "pcmpgtbq", "pcmpgtb");
    addReplaceTerm(*fl, "ptestx", "ptest");
    addReplaceTerm(*fl, "stmxcsrl", "stmxcsr");
    addReplaceTerm(*fl, "ldmxcsrl", "ldmxcsr");
    addReplaceTerm(*fl, "pextrbb", "pextrb");
    addReplaceTerm(*fl, "cflushz", "cflush");
    addReplaceTerm(*fl, "sxd ", "slq ");
    addReplaceTerm(*fl, "stosd", "stosl");
    addReplaceTerm(*fl, "stosdl", "stosl");
    addReplaceTerm(*fl, "fld ", "fldt ");
    addReplaceTerm(*fl, "movdl", "movd");
    addReplaceTerm(*fl, "iretd", "iretl");
    addReplaceTerm(*fl, "scasbb", "scasb");
    addReplaceTerm(*fl, "stosbb", "stosb");
    addReplaceTerm(*fl, "stosd", "stosl");
    addReplaceTerm(*fl, "scasd", "scasl");
    addReplaceTerm(*fl, "scasdl", "scasl");
    addReplaceTerm(*fl, "movsbb", "movsb");
    addReplaceTerm(*fl, "insbb", "insb");
    addReplaceTerm(*fl, "insww", "insw");
    addReplaceTerm(*fl, "outsww", "outsw");
    addReplaceTerm(*fl, "insdl", "insl");
    addReplaceTerm(*fl, "outsbb", "outsb");
    addReplaceTerm(*fl, "outsdl", "outsl");
    addReplaceTerm(*fl, "lodsd", "lodsl");
    addReplaceTerm(*fl, "lodsdl", "lodsl");
    addReplaceTerm(*fl, "lodsbb", "lodsb");
    addReplaceTerm(*fl, "cmpsbb", "cmpsb");
    addReplaceTerm(*fl, "cmpsd", "cmpsl");
    addReplaceTerm(*fl, "popfqq", "popfq");
    addReplaceTerm(*fl, "pushfqq", "pushfq");
    addReplaceTerm(*fl, "invlpgb", "invlpg");
    return fl;
}

void fixExtraOpcodeDressing(char* buf, int bufLen) {
    static FindList* fl = initOpcodeDressingFindList();
    static FindList* strInsnFl = initStrInsnDressingFindList();
    static FindList* nonConvertFl = initNonConvertFindList();
    static FindList* cvtFl = initConvertFindList();
    static FindList* nonVecFl = initNonVecFindList();
    static FindList* pFl = initPInsnSuffixFindList();
    /*
    char* cur = buf;
    bool done = false;
    while (!done && *cur) {
        if (!strncmp(cur, "v", 1) && strncmp(cur, "vf", 2) && strncmp(buf, "vp", 2)) {
            done = true;
            while (*cur && *cur != ' ') {
                ++cur;
            }
            *(cur - 1) = ' ';
        }
        while (*cur && !isspace(*cur)) {
            ++cur;
        }
        if (*cur) {
            ++cur;
        }
    }
    */
    std::string str(buf);

    if (*buf == 'p' || str.find(" p") != std::string::npos) {
        pFl->process(buf, bufLen);
    } else {
        if (str.find("cvt") == std::string::npos) {
            fl->process(buf, bufLen);
            nonConvertFl->process(buf, bufLen);
            strInsnFl->process(buf, bufLen);
        } else {
            cvtFl->process(buf, bufLen);
        }
    }

    if (*buf != 'v') {
        nonVecFl->process(buf, bufLen);
    }

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

void fixFloatSuffixes(char* buf, int bufLen) {
    char* cur = buf;
    bool done = false;
    while (*cur && !done) {
        if ((cur == buf || isspace(*(cur - 1))) && *cur == 'f') {
            if (!strncmp(cur, "fldcw", 5) || 
                !strncmp(cur, "fadds", 5) || 
                !strncmp(cur, "fmul ", 5) || 
                !strncmp(cur, "fimul ", 6) || 
                !strncmp(cur, "fidivl", 6) || 
                !strncmp(cur, "fidivrl", 7) || 
                !strncmp(cur, "fimull", 6) || 
                !strncmp(cur, "ficoml", 6) || 
                !strncmp(cur, "ficompl", 7) || 
                !strncmp(cur, "fisubrl", 7) || 
                !strncmp(cur, "fnstcw", 6) || 
                !strncmp(cur, "fnstsw", 6)) {
                return;
            }
            done = true;
            while (*cur && !isspace(*cur)) {
                ++cur;
            }
            if (*cur) {
                if (*(cur - 1) == 'w') {
                    *(cur - 1) = ' ';
                } else if (*(cur - 1) == 'l') {
                    *(cur - 1) = 's';
                } else if (*(cur - 1) == 'q') {
                    *(cur - 1) = 'l';
                }
            }
        }
        ++cur;
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
    removeUnusedOverridePrefixes(buf, bufLen);
    cleanX86NOP(buf, bufLen);
    removeExtraData16(buf, bufLen);
    removeExtraAddr32(buf, bufLen);
    fixFloatSuffixes(buf, bufLen);
    fixPrefetchSuffix(buf, bufLen);
    fixPFInsnSuffix(buf, bufLen);
    signedOperands(buf, bufLen);
    removeX86Hints(buf, bufLen);
    cleanSpaces(buf, bufLen);
    addMissing0x0(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
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

