
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

#include <iomanip>
#include <string>
#include "InstructionDecoder.h"
#include "Normalization.h"
#include "StringUtils.h"

using namespace Dyninst;
using namespace InstructionAPI;

void dyninst_x86_64_norm(char* buf, int bufLen) {
    toLowerCase(buf, bufLen);
    cleanSpaces(buf, bufLen);
}

int dyninst_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {

   if (nBytes < 1) {
      return -1;
   }

   InstructionDecoder d = InstructionDecoder(inst, nBytes, Arch_x86_64);
   Instruction::Ptr p = d.decode();
   InstructionAPI::Instruction* insn_ptr = p.get();
   assert(insn_ptr);

   strncpy(buf, insn_ptr->format().c_str(), bufLen);
   return 0;
}
