
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
#include <iostream>
#include <sstream>
#include <stdio.h>
#include "bfd.h"
#include "Decoder.h"
#include "Normalization.h"
#include "StringUtils.h"

static void removeRexPrinting(char* buf, int bufLen) {
    std::string result(buf);
   
    if (result.find("rex") == std::string::npos) {
        return;
    }

    // Remove rex prefixes. These are printed if the bytes exist and applied if
    // they are actually used. XED doesn't print them if they are unused.

    removeAtSubStr(result, "rex.WRXB", 9);
    removeAtSubStr(result, "rex.RXB", 8);
    removeAtSubStr(result, "rex.WRB", 8);
    removeAtSubStr(result, "rex.WXB", 8);
    removeAtSubStr(result, "rex.WRX", 8);
    removeAtSubStr(result, "rex.WX", 7);
    removeAtSubStr(result, "rex.WB", 7);
    removeAtSubStr(result, "rex.WR", 7);
    removeAtSubStr(result, "rex.RX", 7);
    removeAtSubStr(result, "rex.RB", 7);
    removeAtSubStr(result, "rex.XB", 7);
    removeAtSubStr(result, "rex.W", 6);
    removeAtSubStr(result, "rex.R", 6);
    removeAtSubStr(result, "rex.X", 6);
    removeAtSubStr(result, "rex.B", 6);
    removeAtSubStr(result, "rex", 4);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
}

static void removeUnusedSegRegs(char* buf, int bufLen) {
    while(!strncmp(buf, "fs ", 3) ||
          !strncmp(buf, "ss ", 3) ||
          !strncmp(buf, "es ", 3) ||
          !strncmp(buf, "gs ", 3) ||
          !strncmp(buf, "cs ", 3) ||
          !strncmp(buf, "ds ", 3)) {

        strcpy(buf, &buf[3]);
    }
    std::string result(buf);
   
    if (result.find("s ") == std::string::npos) {
        return;
    }

    // Remove rex prefixes segment register names that appear without any
    // qualifier. These names are decoded from the bytes preceeding an input
    // instruction. They are removed because the output of objdump indicates
    // that they are not intended to be included in the instruction.
    //
    // Example from objdump:
    //
    //
    removeAtSubStr(result, " fs ", 3);
    removeAtSubStr(result, " ss ", 3);
    removeAtSubStr(result, " es ", 3);
    removeAtSubStr(result, " gs ", 3);
    removeAtSubStr(result, " ds ", 3);
    removeAtSubStr(result, " cs ", 3);

    removeAtSubStr(result, " fs ", 3);
    removeAtSubStr(result, " ss ", 3);
    removeAtSubStr(result, " es ", 3);
    removeAtSubStr(result, " gs ", 3);
    removeAtSubStr(result, " ds ", 3);
    removeAtSubStr(result, " cs ", 3);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
}

bool gnuWillCrash(char* inst, int nBytes) {
    
    // This loop detects the objdump-aborting byte sequences regardless of
    // offset. It will return some false positives, but it will at least allow
    // me to run without issue.
    for (int curByte = 0; curByte < nBytes; curByte++) {
   
        // There are a few cases that Objdump will cause the program to abort on, so
        // I report those as errors.
        if (nBytes - curByte >= 4) {
            if (inst[curByte + 0] == (char)0x8f &&
                (0x03 & (inst[curByte + 1] >> 3)) == 1 &&
                (0x01 & (inst[curByte + 2] >> 2)) == 1 &&
                ((0xf0 & inst[curByte + 3]) == 0xe0 || 
                 (0xf0 & inst[curByte + 3]) == 0xc0) &&
                ((0x0f & inst[curByte + 3]) > 0x0b)) {
                return true;
            }
        }
      
        // These are VEX instructions that GNU fails currently.
        if (nBytes - curByte >= 5 && inst[curByte + 0] == 0x62) {
            if (inst[curByte + 4] == 0x20 || 
                inst[curByte + 4] == 0x22 || 
                inst[curByte + 4] == (char)0xc4) {
             
                if ((inst[curByte + 1] & 0x0d) == 0x01 && 
                    (inst[curByte + 2] & 0x07) == 0x05) {
                    if ((inst[curByte + 3] & 0x60) == 0x20) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

static void removeNonAssemblyPrinting(char* buf, int bufLen) {
    removeUnusedSegRegs(buf, bufLen);
    removeRexPrinting(buf, bufLen);
    removePoundComment(buf, bufLen);
}

int gnu_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   
    if (gnuWillCrash(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen - 1);
    }
    disassemble_info disInfo;
   
    static char fbuf[DECODING_BUFFER_SIZE];
    static FILE* outf = fmemopen(fbuf, DECODING_BUFFER_SIZE - 1, "r+");
    bzero(fbuf, DECODING_BUFFER_SIZE);
    assert(outf != NULL);
    rewind(outf);

    assert(outf != NULL);

    INIT_DISASSEMBLE_INFO(disInfo, outf, (fprintf_ftype)fprintf);
    disInfo.buffer = (bfd_byte*)(inst);
    disInfo.buffer_length = nBytes;
    disInfo.arch = bfd_arch_i386;
    disInfo.mach = bfd_mach_x86_64;

    int rc = 0;

    rc = print_insn_i386((bfd_vma)0, &disInfo);
    fflush(outf);
    strcpy(buf, fbuf);

    if (!strcmp(buf, "gs") || 
        !strcmp(buf, "cs") ||
        !strcmp(buf, "ss") ||
        !strcmp(buf, "fs") ||
        !strcmp(buf, "ds") ||
        !strcmp(buf, "es") ||
        !strcmp(buf, "data16") || 
        !strcmp(buf, "addr32")) {
        
        rc = gnu_x86_64_decode(inst + 1, nBytes - 1, buf, bufLen);
    } else if (!strncmp(buf, "rex", 3) && !strchr(buf, ' ')) {
        rc = gnu_x86_64_decode(inst + 1, nBytes - 1, buf, bufLen);
    }

    /* 
     * The libopcodes function does not exactly match the output of objdump and GDB that
     * are used by binutils. In order to obtain that output, I make these changes here. They
     * should be applied to all decoding so that my use of libopcodes mirrors real tools, 
     * so they are done with decoding instead of normalization.
     */
    removeNonAssemblyPrinting(buf, bufLen);

    buf[bufLen - 1] = 0;
   
    return !rc;
}

static void removeIzRegister(char* buf, int bufLen) {
    std::string result(buf);
   
    if (result.find("iz") == std::string::npos) {
        return;
    }

    // Remove references to the %eiz and %riz registers. They are not used anyway.

    removeAtSubStr(result, "(, %riz, ", 11);
    removeAtSubStr(result, ", %riz, ", 9);
    removeAtSubStr(result, "(, %eiz, ", 11);
    removeAtSubStr(result, ", %eiz, ", 9);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
    
}

static FindList* initFixKRegsFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, " k0", " %k0");
    addReplaceTerm(*fl, " k1", " %k1");
    addReplaceTerm(*fl, " k2", " %k2");
    addReplaceTerm(*fl, " k3", " %k3");
    addReplaceTerm(*fl, " k4", " %k4");
    addReplaceTerm(*fl, " k5", " %k5");
    addReplaceTerm(*fl, " k6", " %k6");
    addReplaceTerm(*fl, " k7", " %k7");
    return fl;
}

static void fixKRegs(char* buf, int bufLen) {
    static FindList* fl = initFixKRegsFindList();
    fl->process(buf, bufLen);
}

static FindList* initJumpHintsFindList() {
    FindList* fl = new FindList(409);
    addReplaceTerm(*fl, "jae, pn", "jae");
    addReplaceTerm(*fl, "ja, pn", "ja");
    addReplaceTerm(*fl, "jbe, pn", "jbe");
    addReplaceTerm(*fl, "jbe, pt", "jbe");
    addReplaceTerm(*fl, "jl, pn", "jl");
    addReplaceTerm(*fl, "js, pn", "js");
    addReplaceTerm(*fl, "jo, pn", "jo");
    addReplaceTerm(*fl, "jg, pn", "jg");
    addReplaceTerm(*fl, "jb, pn", "jb");
    addReplaceTerm(*fl, "jp, pn", "jp");
    addReplaceTerm(*fl, "jp, pt", "jp");
    addReplaceTerm(*fl, "js, pt", "js");
    addReplaceTerm(*fl, "js, pn", "js");
    addReplaceTerm(*fl, "jnp, pt", "jnp");
    addReplaceTerm(*fl, "jnp, pn", "jnp");
    addReplaceTerm(*fl, "jecxz, pn", "jecxz");
    return fl;
}

static void removeJumpHints(char* buf, int bufLen) {
    static FindList* fl = initJumpHintsFindList();
    fl->process(buf, bufLen);
}

int gnu_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {
    if (gnuWillCrash(inst, nBytes)) {
        strncpy(buf, "would_sig", bufLen - 1);
    }
    disassemble_info disInfo;
   
    static char fbuf[DECODING_BUFFER_SIZE];
    static FILE* outf = fmemopen(fbuf, DECODING_BUFFER_SIZE - 1, "r+");
    bzero(fbuf, DECODING_BUFFER_SIZE);
    assert(outf != NULL);
    rewind(outf);

    assert(outf != NULL);

    INIT_DISASSEMBLE_INFO(disInfo, outf, (fprintf_ftype)fprintf);
    disInfo.buffer = (bfd_byte*)(inst);
    disInfo.buffer_length = nBytes;
    disInfo.arch = bfd_arch_i386;
    disInfo.mach = bfd_mach_i386_i386;

    int rc = 0;

    rc = print_insn_i386((bfd_vma)0, &disInfo);
    fflush(outf);
    strcpy(buf, fbuf);

    if (!strcmp(buf, "gs") || 
        !strcmp(buf, "cs") ||
        !strcmp(buf, "ss") ||
        !strcmp(buf, "fs") ||
        !strcmp(buf, "ds") ||
        !strcmp(buf, "es") ||
        !strcmp(buf, "data16") || 
        !strcmp(buf, "addr16")) {
        
        rc = gnu_x86_32_decode(inst + 1, nBytes - 1, buf, bufLen);
    } else if (!strncmp(buf, "rex", 3) && !strchr(buf, ' ')) {
        rc = gnu_x86_32_decode(inst + 1, nBytes - 1, buf, bufLen);
    }

    /* 
     * The libopcodes function does not exactly match the output of objdump and GDB that
     * are used by binutils. In order to obtain that output, I make these changes here. They
     * should be applied to all decoding so that my use of libopcodes mirrors real tools, 
     * so they are done with decoding instead of normalization.
     */
    removeNonAssemblyPrinting(buf, bufLen);

    buf[bufLen - 1] = 0;
   
    return !rc;
}


void gnu_x86_64_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    removeUnusedRepPrefixes(buf, bufLen);
    removeUnusedOverridePrefixes(buf, bufLen);
    removeUnused64BitSegRegs(buf, bufLen);
    removeIzRegister(buf, bufLen);
    removeX86Hints(buf, bufLen);
    removeJumpHints(buf, bufLen);
    fixKRegs(buf, bufLen);
    signedOperands(buf, bufLen);
    cleanSpaces(buf, bufLen);
    cleanX86NOP(buf, bufLen);
}

void gnu_x86_32_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    removeUnusedRepPrefixes(buf, bufLen);
    removeUnusedOverridePrefixes(buf, bufLen);
    removeIzRegister(buf, bufLen);
    removeX86Hints(buf, bufLen);
    removeJumpHints(buf, bufLen);
    fixKRegs(buf, bufLen);
    signedOperands(buf, bufLen);
    cleanSpaces(buf, bufLen);
    cleanX86NOP(buf, bufLen);
}
