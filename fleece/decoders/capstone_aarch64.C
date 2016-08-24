
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

#include "Normalization.h"
#include "capstone/capstone.h"

int capstone_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {

   csh handle;
   cs_insn *insn;
   size_t count;

   if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
      return -1;
   }

   int nInsns = cs_disasm(handle, (uint8_t*)inst, nBytes, 0x1000, 0, &insn);
   
   if (nInsns < 1) {
      return -1;
   }
   
   snprintf(buf, bufLen, "%s %s", insn[0].mnemonic, insn[0].op_str);
   cs_free(insn, nInsns);
   cs_close(&handle);
   return 0;

}

void capstone_aarch64_norm(char* buf, int bufLen) {

}
