
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

#include "Normalization.h"
#include "Mystring.h"
#include <iomanip>
#include "llvm_common.h"

static const char* LLVMCallback(void* info, uint64_t refVal, uint64_t* refType, uint64_t refPC, const char** refName) {

   *refType = LLVMDisassembler_ReferenceType_InOut_None;
   return nullptr;

}

int llvm_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {

   static LLVMDisasmContextRef disasm = LLVMCreateDisasm("x86_64-linux-gnu", nullptr, 0, nullptr, LLVMCallback);

   size_t bytesUsed = LLVMDisasmInstruction(disasm, (uint8_t*)inst, nBytes, 0, buf, (size_t)bufLen);

   return !bytesUsed;
}

void llvm_x86_64_norm(char* buf, int bufLen) {

}
