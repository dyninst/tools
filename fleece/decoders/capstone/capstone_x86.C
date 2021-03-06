
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

#include <iostream>
#include "Decoder.h"
#include "Normalization.h"
#include "capstone/capstone.h"

FindList* initSwapTestOperandsFindList() {
    FindList* fl = new FindList(877);
    Normalization::addOperandSwapTerm(*fl, "test", 0, 1);
    return fl;
}

void swapTestOperands(char* buf, int bufLen) {
    static FindList* fl = initSwapTestOperandsFindList();
    fl->process(buf, bufLen);
}

bool capstoneWillCrash(char* inst, int nBytes) {
    for (int i = 0; i < nBytes - 4; ++i) {
        if (nBytes >= 5 && inst[i + 1] == (char)0x62 && inst[i + 4] == (char)0x03) {
            return true;
        }
    }
    return false;
}

csh makeX86CSHandle() {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "ERROR: Capstone could not start!\n";
        exit(-1);
    }
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    return handle;
}

int capstone_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {

    static csh handle = makeX86CSHandle();
    cs_insn *insn;

    if (capstoneWillCrash(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen);
        return 0;
    }

    int nInsns = cs_disasm(handle, (uint8_t*)inst, nBytes, 0, 0, &insn);
   
    if (nInsns < 1) {
        return -1;
    }
   
    snprintf(buf, bufLen, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, nInsns);
    return 0;

}

FindList* initAddMissingCommaAfter1FindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, " $1 ", " $1, ");
    return fl;
}

void addMissingCommaAfter1(char* buf, int bufLen) {
    static FindList* fl = initAddMissingCommaAfter1FindList();
    fl->process(buf, bufLen);
}

FindList* initSwapPtestOperandsFindList() {
    FindList* fl = new FindList(877);
    Normalization::addOperandSwapTerm(*fl, "ptest", 0, 1);
    Normalization::addReplaceTerm(*fl, "{%k0}", "");
    return fl;
}

void swapPtestOperands(char* buf, int bufLen) {
    static FindList* fl = initSwapPtestOperandsFindList();
    fl->process(buf, bufLen);
}

csh makeX86_32CSHandle() {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        std::cerr << "ERROR: Capstone could not start!\n";
        exit(-1);
    }
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    return handle;
}

int capstone_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {

    static csh handle = makeX86_32CSHandle();
    cs_insn *insn;

    if (capstoneWillCrash(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen);
        return 0;
    }

    int nInsns = cs_disasm(handle, (uint8_t*)inst, nBytes, 0, 0, &insn);
   
    if (nInsns < 1) {
        return -1;
    }
   
    snprintf(buf, bufLen, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, nInsns);
    return 0;

}

void capstone_x86_norm(char* buf, int bufLen) {
    swapPtestOperands(buf, bufLen);
    addMissingCommaAfter1(buf, bufLen);
}
Decoder* dec_capstone_x86_32 = new Decoder(&capstone_x86_32_decode, NULL, 
            &capstone_x86_norm, "capstone", "x86_32");
Decoder* dec_capstone_x86_64 = new Decoder(&capstone_x86_64_decode, NULL, 
            &capstone_x86_norm, "capstone", "x86_64");
