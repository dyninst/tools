
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
#include "Normalization.h"
#include "capstone/capstone.h"

csh makePpcCsHandle() {
    csh handle;
    if (cs_open(CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK) {
        std::cerr << "ERROR: Capstone could not init handle!\n";
        exit(-1);
    }
    return handle;
}

int capstone_ppc_decode(char* inst, int nBytes, char* buf, int bufLen) {

    static csh handle = makePpcCsHandle();
    cs_insn *insn;

    int nInsns = cs_disasm(handle, (uint8_t*)inst, nBytes, 0, 0, &insn);
   
    if (nInsns < 1) {
        return -1;
    }
   
    snprintf(buf, bufLen, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, nInsns);
    return 0;
}

void capstone_ppc_norm(char* buf, int bufLen) {
}
