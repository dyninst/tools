
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
#include "Decoder.h"
#include "Normalization.h"
#include "StringUtils.h"

int gnu_ppc_decode(char* inst, int nBytes, char* buf, int bufLen) {
     
    disassemble_info disInfo;
    static char fbuf[DECODING_BUFFER_SIZE];
    static FILE* outf = fmemopen(fbuf, DECODING_BUFFER_SIZE - 1, "r+");
    bzero(fbuf, DECODING_BUFFER_SIZE);
    assert(outf != NULL);
    rewind(outf);

    INIT_DISASSEMBLE_INFO(disInfo, outf, (fprintf_ftype)fprintf);
    disInfo.buffer = (bfd_byte*)(inst);
    disInfo.buffer_length = nBytes;
    disInfo.arch = bfd_arch_powerpc;
    disInfo.mach = bfd_mach_ppc64;
    disassemble_init_powerpc (&disInfo);
    
    int rc = 0;

    rc = print_insn_big_powerpc((bfd_vma)0, &disInfo);
    fflush(outf);
    strcpy(buf, fbuf);
    
    return !(rc > 0);
}

Decoder* dec_gnu_ppc = new Decoder(&gnu_ppc_decode, NULL, NULL, "gnu", "ppc");
