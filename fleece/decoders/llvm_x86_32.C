
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

#include "Decoder.h"
#include "llvm_common.h"
#include "Normalization.h"
#include "StringUtils.h"

static const char* LLVMCallback(void* info, uint64_t refVal, uint64_t* refType,
        uint64_t refPC, const char** refName) {

    *refType = LLVMDisassembler_ReferenceType_InOut_None;
    return nullptr;
}

static bool llvmWillAssert(char* inst, int nBytes) {
    // Asserted on: 67    62 c1 3c d6 56 34 a5 de 3e 50 db b0 d3 5f
    //              67 64 62 e1 45 40 da 7c e2 f6 01 0f 5e a7 5f
    //              67    62 62 5d 12 2c 54 a0 27 d2 36 64 97 6c
    //              67    62 e2 ad 62 0d 2c 60 eb d7 a7 c6 f5 ec af
    //              67    62 f3 1d 22 1e 94 e4 aa d3 59 63 18 a9 a1
    //              67    62 d1 5d 86 e4 6c e6 f7 2d fc 32 27 e7 c7
    //              67    62 d3 ad e3 23 4c 66 39 61 7a c6 17 d1 0a
    //              67    62 53 ed 66 50 3c e6 bd 9a ac b2 ec f8 29
    //              67    62 42 1d 01 99 6c 27 a1 69 9f 1b ad 81 8b
    //              67    62 51 14 e5 58 74 a6 db b9 c5 9a 4a 8b e6
    //              67    62 d1 74 c3 5d b4 e4 2c 71 4e 69 11 9b c3
    //              67    62 51 6d 01 dc 34 20 3f 7c ac 84 a7 c0 8a
    //              67    62 41 65 a1 f9 5c 27 75 23 70 91 fb 14
    //              67    62 e1 5d 03 60 ac a2 c0 52 5b 8b b7 7f f9
    for (int i = 0; i < nBytes - 6; ++i) {
        if (inst[i + 0] == (char)0x67) {
            for (int j = i + 1; j < nBytes - 6; ++j) {
                if (inst[j + 0] == (char)0x62 && (((char)0x0F) & inst[j + 1]) < (char)0x04 && (((char)0x0F) & inst[j + 1]) > (char)0x00 &&
                    (((char)0x04) & inst[j + 2]) == (char)0x04) {
                    return true;
                }
            }
        }
        if (inst[i + 0] == (char)0x67 && inst[i + 1] == (char)0x62 && inst[i + 2] == (char)0xf2) {
            return true;
        }
        if (inst[i + 0] == (char)0x67 && inst[i + 1] == (char)0x62 && inst[i + 3] == (char)0xa4 && inst[i + 4] == (char)0x8d) {
            return true;
        }
    }
    for (int i = 0; i < nBytes - 5; ++i) {
        if (inst[i + 0] == (char)0x62 && inst[i + 4] == (char)0xc2) {
            return true;
        }
    }
    return false;
}

int llvm_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {

    if (llvmWillAssert(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen);
        return 0;
    }

    static LLVMDisasmContextRef disasm = 
            LLVMCreateDisasm("i386-linux-gnu", 
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

    int rc = !bytesUsed;
    if (!strcmp(buf, "\tgs") || 
        !strcmp(buf, "\tcs") ||
        !strcmp(buf, "\tss") ||
        !strcmp(buf, "\tfs") ||
        !strcmp(buf, "\tds") ||
        !strcmp(buf, "\tes") ||
        !strcmp(buf, "\trep") ||
        !strcmp(buf, "\trepz") ||
        !strcmp(buf, "\tlock") ||
        !strcmp(buf, "\trepnz") ||
        !strcmp(buf, "\trepne") ||
        !strcmp(buf, "\tdata16") || 
        !strcmp(buf, "\taddr16") ||
        !strcmp(buf, "\taddr32") ||
        !strcmp(buf, "\txacquire") ||
        !strcmp(buf, "\txrelease")) {
        if (llvm_x86_32_decode(inst + 1, nBytes - 1, buf, bufLen)) {
            rc = -1;
        }
    }
    
    return rc;
}

void llvm_x86_32_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    decToHexConstants(buf, bufLen);
    removeImplicitK0(buf, bufLen);
    addImpliedX86Index(buf, bufLen);
    cleanX86NOP(buf, bufLen);
    fixCallSuffix(buf, bufLen);
}
Decoder* dec_llvm_x86_32 = new Decoder(&llvm_x86_32_decode, &LLVMInit, 
            &llvm_x86_32_norm, "llvm", "x86_32");
