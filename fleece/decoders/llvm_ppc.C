
/*
 * See peach/COPYRIGHT for copyright information.
 *
 * This file is a part of Peach.
 *
 * Peach is free software; you can redistribute it and/or modify it under the
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

#include <sys/mman.h>
#include "llvm_common.h"
#include "Normalization.h"
#include "StringUtils.h"

#include <iostream>
#include <iomanip>

using namespace llvm;

static const char* LLVMCallback(void* info, uint64_t refVal, uint64_t* refType, uint64_t refPC, const char** refName) {

    *refType = LLVMDisassembler_ReferenceType_InOut_None;
    return nullptr;

}

bool wouldLlvmPpcInsnSig(char* insn, int nBytes) {
    
    if (nBytes < 4) {
        return false;
    }

    if ((insn[0] == (char)0xFC || insn[0] == (char)0xFD || insn[0] ==
            (char)0xFE || insn[0] == (char)0xFF) && 
            (insn[3] == 0x0B || insn[3] == 0x0A || insn[3] == 0x4A)) {
        return true;
    }

    if (insn[0] == 0x7C && (insn[3] == (char)0x9D || insn[3] ==
            (char)0xDD || insn[3] == (char)0x5D || insn[3] == 0x1D)) {

        return true;
    }

    if ((insn[0] == 0x7D || insn[0] == 0x7E || insn[0] == 0x7F) &&
            (insn[3] = 0x1D || insn[3] == 0x5D || insn[3] ==
            (char)0xDD)) {

        return true;
    }

    if ((insn[0] >= 0x10 && insn[0] <= 0x13) && (insn[3] == 0x0D ||
            insn[3] == 0x4D || insn[3] == (char)0x8D || insn[3] ==
            (char)0xCD)) {

        return true;
    }

    return false;
}

int llvm_ppc_decode(char* inst, int nBytes, char* buf, int bufLen) {

    static LLVMDisasmContextRef disasm = LLVMCreateDisasm(
            "powerpc64-unknown-unknown", 
            nullptr, 
            0, 
            nullptr, 
            LLVMCallback);

    if (wouldLlvmPpcInsnSig(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen);
        return 1;
    }

    /*
    for (int j = 0; j < nBytes; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)inst[j] << " ";
    }
    std::cout << "\n" << std::dec;
    //*/

    size_t bytesUsed = LLVMDisasmInstruction(
            disasm, 
            (uint8_t*)inst, 
            nBytes, 
            0, 
            buf, 
            (size_t)bufLen);

    if (!bytesUsed) {
       strncpy(buf, "llvm_decoding_error", bufLen);
    }

    return !bytesUsed;
}

void llvm_ppc_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
}

