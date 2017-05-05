
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
#include "aarch64_common.h"
#include "Normalization.h"
#include "capstone/capstone.h"

void makeIndexesDecimal(char* buf, int bufLen) {

    char tmp[bufLen];
    char* tmpStart = &tmp[0];
    char* cur = buf;
    while (*cur) {
        if (*(cur + 1) && *(cur + 1) == '[' && 
            *(cur + 2) && *(cur + 2) == '0' && 
            *(cur + 3) && *(cur + 3) == 'x') {
            
            cur += 2;
            char* place = cur;
            char* digitsEnd = NULL;
            long long int val = strtoll(cur, &digitsEnd, 16);
            strcpy(tmpStart, digitsEnd);
            place += snprintf(place, bufLen - (place - buf), "%lld", val);
            strncpy(place, tmpStart, bufLen - (place - buf));
        }
        cur++;
    }
}

csh makeAarch64CSHandle() {
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        std::cerr << "ERROR: Capstone failed to init handle!\n";
        exit(-1);
    }
    return handle;
}

int capstone_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {

    static csh handle = makeAarch64CSHandle();
    cs_insn *insn;
    int nInsns = cs_disasm(handle, (uint8_t*)inst, nBytes, 0, 0, &insn);
   
    if (nInsns < 1) {
        return -1;
    }
   
    snprintf(buf, bufLen, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, nInsns);
    return 0;

}

void removeADRPPound(char* buf, int bufLen) {
    if (!strncmp(buf, "adrp", 4)) {
        char* cur = buf;
        while (*cur) {
            if (*cur == '#') {
                *cur = ' ';
            }
            ++cur;
        }
    }
}

void capstone_aarch64_norm(char* buf, int bufLen) {
    makeIndexesDecimal(buf, bufLen);
    removeADRPPound(buf, bufLen);
    cleanSpaces(buf, bufLen);
}
