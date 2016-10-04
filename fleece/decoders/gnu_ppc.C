
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


#define PACKAGE 1
#define PACKAGE_VERSION 1

#include <algorithm>
#include <dis-asm.h>
#include <sstream>
#include <stdio.h>
#include "bfd.h"
#include "Normalization.h"
#include "StringUtils.h"

int gnu_ppc_decode(char* inst, int nBytes, char* buf, int bufLen) {
     
    disassemble_info disInfo;

    // Since we will be treating the buffer as a file, we need to be sure that
    // we zero the entire buffer ahead of time to prevent any of the previous
    // value showing.
    bzero(buf, bufLen);
   
    FILE* outf = fmemopen(buf, bufLen - 1, "r+");

    assert(outf != NULL);

    INIT_DISASSEMBLE_INFO(disInfo, outf, (fprintf_ftype)fprintf);
    disInfo.buffer = (bfd_byte*)(inst);
    disInfo.buffer_length = nBytes;
    disInfo.arch = bfd_arch_powerpc;
    disInfo.mach = bfd_mach_ppc64;
    disassemble_init_powerpc (&disInfo);
    
    int rc = 0;

    rc = print_insn_big_powerpc((bfd_vma)0, &disInfo);

    fclose(outf);

    return !(rc > 0);
}

void gnu_ppc_norm(char* buf, int bufLen) {
  
    // NORMALIZATION STEPS
    
    toLowerCase(buf, bufLen);
    cleanSpaces(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
}
