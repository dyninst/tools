
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

#include "Normalization.h"
#include <algorithm>
#include <sstream>
#include <stdio.h>
#include <iostream>
#include "Mystring.h"
#include <iomanip>
#include <dis-asm.h>
#include "bfd.h"

int gnu_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   
   // This loop detects the objdump-aborting byte sequences regardless of
   // offset. It will return some false positives, but it will at least allow
   // me to run without issue.
   for (int curByte = 0; curByte < nBytes; curByte++) {
   
      // There are a few cases that Objdump will cause the program to abort on, so
      // I report those as errors.
      if (nBytes - curByte >= 4) {
         if (inst[curByte + 0] == (char)0x8f                                  &&
             (0x03 & (inst[curByte + 1] >> 3)) == 1                           &&
             (0x01 & (inst[curByte + 2] >> 2)) == 1                           &&
             ((0xf0 & inst[curByte + 3]) == 0xe0 || (0xf0 & inst[curByte + 3]) == 0xc0) &&
             ((0x0f & inst[curByte + 3]) > 0x0b)) {

            // Return an error
            return -1;
         }
      }
      
      // These are VEX instructions that GNU fails currently.
      if (nBytes - curByte >= 5 && inst[curByte + 0] == 0x62) {
         if (inst[curByte + 4] == 0x20 || inst[curByte + 4] == 0x22 || inst[curByte + 4] == (char)0xc4) {
            if ((inst[curByte + 1] & 0x0d) == 0x01 && (inst[curByte + 2] & 0x07) == 0x05) {
               if ((inst[curByte + 3] & 0x60) == 0x20) {
                  return -1;
               }
            }
         }
      }
   }

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
   disInfo.arch = bfd_arch_i386;
   disInfo.mach = bfd_mach_x86_64;

   int rc = 0;

   rc = print_insn_i386((bfd_vma)0, &disInfo);
   
   fclose(outf);

   if (!strcmp(buf, "gs") || 
       !strcmp(buf, "cs") ||
       !strcmp(buf, "ss") ||
       !strcmp(buf, "fs") ||
       !strcmp(buf, "ds") ||
       !strcmp(buf, "es") ||
       !strcmp(buf, "data16")) {
      //if (gnu_x86_64_decode(inst + 1, nBytes - 1, buf + strlen(buf), bufLen - strlen(buf))) {
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

void removeRexPrefix(char* buf, int bufLen) {
   
   // Check that the buffer is long enough for a rex prefix.
   if (bufLen < 4) {
      return;
   }

   // Confirm that the instruction begins with a rex prefix.
   if (strncmp(buf, "rex.", 4)) {
      return;
   }

   //std::cout << "Starting with:\n\t" << buf;

   // Go until we finish the rex prefix and the space after.
   char* cur = buf;
   while (*cur && *cur != ' ') {
      cur++;
   }
   cur++;

   char* place = buf;
   while (*cur) {
      *place = *cur;
      place++;
      cur++;
   }
   *place = 0;

   //std::cout << "\n\t" << buf << "\n";

}

void removePoundComment(char* buf, int bufLen) {
   while (*buf && *buf != '#') {
      buf++;
   }
   *buf = 0;
}

void trimSegRegs(char* buf, int bufLen) {
   char* place = buf;
   char* cur = buf;

   // Trim leading segment registers which could be:
   // cs, ds, es, fs, gs, ss
   // and are only meaningless if leading.

   while (*cur) {

      if ((*cur == 'c' || *cur == 'd' || *cur == 'e' || *cur == 'e' ||
              *cur == 'f' || *cur == 'g' || *cur == 's') && 
              *(cur + 1) == 's' && 
              *(cur + 2) == ' ') {
         cur += 3;
      } else {
         while (*cur && *cur != ' ') {
            *place = *cur;
            cur++;
            place++;
         }
         
         *place = *cur;
         cur++;
         place++;
      }
   }

   *place = *cur;
}

void removeExtraPrefixes(char* buf, int bufLen) {
   bool seenLock = false;
   bool seenRep = false;
   bool seenData16 = false;
   bool seenAddr32 = false;

   char* place = buf;
   char* cur = buf;
   char* end = buf;

   while (*end) {
      end++;
   }

   while (*cur) {

      if (end - cur >= 4 && !strncmp(cur, "lock", 4)) {
         if (seenLock) {
            cur += 4;
         }
         seenLock = true;
      } else if (end - cur >= 5 && !strncmp(cur, "repnz", 5)) {
         if (seenRep) {
            cur += 5;
         }
         seenRep = true;
      } else if (end - cur >= 5 && !strncmp(cur, "repne", 5)) {
         if (seenRep) {
            cur += 5;
         }
         seenRep = true;
      } else if (end - cur >= 4 && !strncmp(cur, "repz", 4)) {
         if (seenRep) {
            cur += 4;
         }
         seenRep = true;
      } else if (end - cur >= 4 && !strncmp(cur, "repe", 4)) {
         if (seenRep) {
            cur += 4;
         }
         seenRep = true;
      } else if (end - cur >= 3 && !strncmp(cur, "rep", 3)) {
         if (seenRep) {
            cur += 3;
         }
         seenRep = true;
      } else if (end - cur >= 6 && !strncmp(cur, "data16", 6)) {
         if (seenData16) {
            cur += 6;
         }
         seenData16 = true;
      } else if (end - cur >= 6 && !strncmp(cur, "addr32", 6)) {
         if (seenAddr32) {
            cur += 6;
         }
         seenAddr32 = true;
      }

      while (*cur && *cur != ' ') {
         *place = *cur;
         place++;
         cur++;
      }

      *place = *cur;
      cur++;
      place++;
   }
   *place = *cur;
}

int gnu_x86_64_norm(char* buf, int bufLen) {

   cleanSpaces(buf, bufLen);
   toLowerCase(buf, bufLen);
   spaceAfterCommas(buf, bufLen);
   removeRexPrefix(buf, bufLen);
   removePoundComment(buf, bufLen);
   trimHexZeroes(buf, bufLen);
   trimHexFs(buf, bufLen);
   trimSegRegs(buf, bufLen);
   removeExtraPrefixes(buf, bufLen);

   std::string result(buf);
   
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
   
   removeAtSubStr(result, ", %riz, ", 9);

   strncpy(buf, result.c_str(), bufLen);
   buf[bufLen - 1] = 0;

   cleanSpaces(buf, bufLen);
   

}
