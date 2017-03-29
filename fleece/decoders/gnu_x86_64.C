
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

int gnu_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   
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

                // Return an error
                strncpy(buf, "would_sig", bufLen - 1);
                return 0;
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
                        // Return an error
                        strncpy(buf, "would_sig", bufLen - 1);
                        return 0;
                    }
                }
            }
        }
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
        if (gnu_x86_64_decode(inst + 1, nBytes - 1, buf, bufLen)) {
            rc = -1;
        }
    } else if (!strncmp(buf, "rex", 3)) {
        char* cur = buf;
        while (*cur && *cur != ' ') {
            cur++;
        }
        if (!*cur) {
            if (gnu_x86_64_decode(inst + 1, nBytes - 1, buf, bufLen)) {
                rc = -1;
            }
        }
    }

    buf[bufLen - 1] = 0;
   
    return !rc;
}

void removeRexPrinting(char* buf, int bufLen) {
    std::string result(buf);
   
    if (result.find("rex") == std::string::npos) {
        return;
    }

    // Remove rex prefixes. These are printed if the bytes exist and applied if
    // they are actually used. XED doesn't print them if they are unused.

    removeAtSubStr(result, "rex.wrxb", 8);
    removeAtSubStr(result, "rex.rxb", 7);
    removeAtSubStr(result, "rex.wrb", 7);
    removeAtSubStr(result, "rex.wrb", 7);
    removeAtSubStr(result, "rex.wxb", 7);
    removeAtSubStr(result, "rex.wrx", 7);
    removeAtSubStr(result, "rex.wx", 6);
    removeAtSubStr(result, "rex.wb", 6);
    removeAtSubStr(result, "rex.wr", 6);
    removeAtSubStr(result, "rex.rx", 6);
    removeAtSubStr(result, "rex.rb", 6);
    removeAtSubStr(result, "rex.xb", 6);
    removeAtSubStr(result, "rex.w", 5);
    removeAtSubStr(result, "rex.r", 5);
    removeAtSubStr(result, "rex.x", 5);
    removeAtSubStr(result, "rex.b", 5);
    removeAtSubStr(result, "rex", 3);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
}

void removeIzRegister(char* buf, int bufLen) {
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

void gnu_x86_64_norm(char* buf, int bufLen) {

    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    removeRexPrinting(buf, bufLen);
    removeIzRegister(buf, bufLen);
    removePoundComment(buf, bufLen);
    cleanSpaces(buf, bufLen);
}
