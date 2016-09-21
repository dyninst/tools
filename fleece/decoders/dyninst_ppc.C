
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

#include "Decoder.h"
#include "Normalization.h"
#include "InstructionDecoder.h"
#include "StringUtils.h"

using namespace Dyninst;
using namespace InstructionAPI;

int dyninst_ppc_decode(char* inst, int nBytes, char* buf, int bufLen) {
   
    InstructionDecoder d(inst, nBytes, Arch_ppc64);
    Instruction::Ptr p = d.decode();
    strncpy(buf, p->format().c_str(), bufLen);

    return 0;
}

void dyninst_ppc_norm(char* buf, int bufLen) {
    toLowerCase(buf, bufLen);
}
