
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

#include <sys/mman.h>
#include "Decoder.h"
#include "llvm_common.h"
#include "Normalization.h"
#include "StringUtils.h"

using namespace llvm;


static const char* LLVMCallback(void* info, uint64_t refVal, uint64_t* refType, uint64_t refPC, const char** refName) {

    *refType = LLVMDisassembler_ReferenceType_InOut_None;
    return nullptr;

}

int llvm_armv6_decode(char* inst, int nBytes, char* buf, int bufLen) {

    static LLVMDisasmContextRef disasm = LLVMCreateDisasm(
            "armv6m-linux-gnu", 
            nullptr, 
            0, 
            nullptr, 
            LLVMCallback);

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

void llvm_armv6_norm(char* buf, int bufLen) {

    // NORMALIZATION STEPS
    cleanSpaces(buf, bufLen);
    removeComments(buf, bufLen);
}

Decoder* dec_llvm_armv6 = new Decoder(&llvm_armv6_decode, &LLVMInit,
            &llvm_armv6_norm, "llvm", "armv6");
