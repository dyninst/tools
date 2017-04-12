
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

#include "llvm_common.h"
#include "Normalization.h"
#include "StringUtils.h"

static const char* LLVMCallback(void* info, uint64_t refVal, uint64_t* refType,
        uint64_t refPC, const char** refName) {

    *refType = LLVMDisassembler_ReferenceType_InOut_None;
    return nullptr;
}

bool llvmWillAssert(char* inst, int nBytes) {
    if (nBytes >= 5 && inst[0] == (char)0x62 && inst[4] == (char)0xc2) {
        return true;
    }
    return false;
}

int llvm_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {

    if (llvmWillAssert(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen);
        return 0;
    }

    static LLVMDisasmContextRef disasm = 
            LLVMCreateDisasm("x86_64-linux-gnu", 
                             nullptr, 
                             0, 
                             nullptr, 
                             LLVMCallback);

    size_t bytesUsed = 
            LLVMDisasmInstruction(disasm, 
                                  (uint8_t*)inst, 
                                  nBytes, 
                                  0, 
                                  buf, 
                                  (size_t)bufLen);

    return !bytesUsed;
}

void llvm_x86_64_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    trimHexFs(buf, bufLen);
    trimHexZeroes(buf, bufLen);
    cleanX86NOP(buf, bufLen);
}
