
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

#include <assert.h>
#include "Normalization.h"
#include "Mystring.h"
#include "Decoder.h"
#include "Alias.h"
#include "InstructionDecoder.h"

using namespace Dyninst;
using namespace InstructionAPI;

bool hasShiftedConstant(char* buf, int bufLen) {
   return !strncmp(buf, "stp", 3)  ||
          !strncmp(buf, "stnp", 4) ||
          !strncmp(buf, "ldp", 3)  ||
          !strncmp(buf, "ldnp", 4);
}

void formatShiftedConstants(char* buf, int bufLen) {
   if (!hasShiftedConstant(buf, bufLen)) {
      return;
   }

   //std::cout << "Converted: " << buf << "\n";
   
   int commaCount = 0;
   char* cur = buf;
   while(*cur && commaCount < 3) {
      if (*cur == ',') {
         commaCount++;
      }
      cur++;
   }
   
   for (int i = 0; i < 3; i++) {
      if (!*cur) {
         return;
      }
      cur++;
   }

   //std::cout << "Hex string starts as: " << cur << "\n";

   char* hexStart = cur;
   bool isSigned = false;
   if (*hexStart == 'f' && *(hexStart + 1) != ' ' && *(hexStart + 2) != ' ') {
      isSigned = true;
   }

   while (*cur && *cur != ',') {
      cur++;
   }

   *cur = 0;
   cur++;

   for (int i = 0; i < 7; i++) {
      if (!*cur) {
         return;
      }
      cur++;
   }
   
   // If the value wasn't signed, replace the old value in place with the new
   // one.
   if (!isSigned) {
      shiftHex(hexStart, getCharHexVal(*cur), hexStart, buf + bufLen - hexStart);
   } else {
      // Since the value was signed, we'll want to remove the first character
      // because it is really overflow from the signed representation. We will
      // write the hex vale back one place sooner and overwrite the first
      // character with the 'x' from the leading '0x'.
      
      shiftHex(hexStart, getCharHexVal(*cur), hexStart - 1, buf + bufLen - hexStart + 1);
      *(hexStart - 1) = 'x';

   }
   //std::cout << "\t" << buf << "\n";

}

int dyninst_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   
   if (isAarch64SysRegInsn(inst, nBytes, buf, bufLen)) {
      return 0;
   }
   
   InstructionDecoder d(inst, nBytes, Arch_aarch64);
   Instruction::Ptr p = d.decode();
   strncpy(buf, p->format().c_str(), bufLen);

   return 0;
}

void dyninst_aarch64_norm(char* buf, int bufLen) {

   toLowerCase(buf, bufLen);
   
   //removeCharacter(buf, bufLen, ']');
   //removeCharacter(buf, bufLen, '[');
   removeTrailing(buf, bufLen, ", pstate");
   removeTrailing(buf, bufLen, ", pc");
   removeFirst(buf, bufLen, "pc + ");
   replaceStr(buf, bufLen, " <<", ", lsl");
   replaceStr(buf, bufLen, " +", ",");
   removeHexBrackets(buf, bufLen);
   place0x(buf, bufLen);
   formatShiftedConstants(buf, bufLen);
   trimHexFs(buf, bufLen);
   removeADRPZeroes(buf, bufLen);
   removeTrailing(buf, bufLen, ", lsl 0x0");
   replaceStr(buf, bufLen, " asr", ", asr");
   replaceStr(buf, bufLen, " lsr", ", lsr");
   replaceStr(buf, bufLen, " ror", ", ror");
   
   buf[bufLen - 1] = 0;

}

void aliasRegisterSet(const char* prefix1, const char* suffix1, const char* prefix2, const char* suffix2) {
   int plen1 = strlen(prefix1);
   int plen2 = strlen(prefix2);
   
   char* str1 = (char*)malloc(32 + plen1 + strlen(suffix1));
   char* str2 = (char*)malloc(32 + plen2 + strlen(suffix2));

   assert(str1 != NULL && str2 != NULL);

   strcpy(str1, prefix1);
   strcpy(str2, prefix2);

   strcpy(str1 + plen1 + 1, suffix1);
   strcpy(str2 + plen2 + 1, suffix2);

   for (str1[plen1] = '0'; str1[plen1] <= '9'; str1[plen1]++) {
      str2[plen2] = str1[plen1];
      Alias::addAlias(str1, str2);
   }

   strcpy(str1 + plen1 + 2, suffix1);
   strcpy(str2 + plen2 + 2, suffix2);

   for(str1[plen1] = '1'; str1[plen1] <= '3'; str1[plen1]++) {
      for (str1[plen1 + 1] = '0'; str1[plen1 + 1] <= '9'; str1[plen1 + 1]++) {
         str2[plen2] = str1[plen1];
         str2[plen2 + 1] = str1[plen1 + 1];
         Alias::addAlias(str1, str2);
      }
   }

   free(str1);
   free(str2);
}

int dyninst_aarch64_init(void) {

   /*
   aliasRegisterSet("hq", "", "v", ".2");
   aliasRegisterSet("hq", ",", "v", ".2,");
   aliasRegisterSet("hq", "", "v", ".2d");
   aliasRegisterSet("hq", ",", "v", ".2d,");
   aliasRegisterSet("hq", "", "v", ".4s");
   aliasRegisterSet("hq", ",", "v", ".4s,");
   aliasRegisterSet("hq", "", "v", ".8h");
   aliasRegisterSet("hq", ",", "v", ".8h,");
   aliasRegisterSet("hq", "", "v", ".16b");
   aliasRegisterSet("hq", ",", "v", ".16b,");
   
   aliasRegisterSet("q", "", "v", ".2");
   aliasRegisterSet("q", ",", "v", ".2,");
   aliasRegisterSet("q", "", "v", ".2d");
   aliasRegisterSet("q", ",", "v", ".2d,");
   aliasRegisterSet("q", "", "v", ".4s");
   aliasRegisterSet("q", ",", "v", ".4s,");
   aliasRegisterSet("q", "", "v", ".8h");
   aliasRegisterSet("q", ",", "v", ".8h,");
   aliasRegisterSet("q", "", "v", ".16b");
   aliasRegisterSet("q", ",", "v", ".16b,");

   aliasRegisterSet("d", "", "v", ".1d");
   aliasRegisterSet("d", ",", "v", ".1d,");
   aliasRegisterSet("d", "", "v", ".2s");
   aliasRegisterSet("d", ",", "v", ".2s,");
   aliasRegisterSet("d", "", "v", ".4h");
   aliasRegisterSet("d", ",", "v", ".4h,");
   aliasRegisterSet("d", "", "v", ".8b");
   aliasRegisterSet("d", ",", "v", ".8b,");

   Alias::addAlias("pldl1keep,", "0x0,");
   Alias::addAlias("pldl1strm,", "0x1,");
   Alias::addAlias("pldl2keep,", "0x2,");
   Alias::addAlias("pldl2strm,", "0x3,");
   Alias::addAlias("pldl3keep,", "0x4,");
   Alias::addAlias("pldl3strm,", "0x5,");
   Alias::addAlias("plil1keep,", "0x8,");
   Alias::addAlias("plil1strm,", "0x9,");
   Alias::addAlias("plil2keep,", "0xa,");
   Alias::addAlias("plil2strm,", "0xb,");
   Alias::addAlias("plil3keep,", "0xc,");
   Alias::addAlias("plil3strm,", "0xd,");
   Alias::addAlias("pstl1keep,", "0x10,");
   Alias::addAlias("pstl1strm,", "0x11,");
   Alias::addAlias("pstl2keep,", "0x12,");
   Alias::addAlias("pstl2strm,", "0x13,");
   Alias::addAlias("pstl3keep,", "0x14,");
   Alias::addAlias("pstl3strm,", "0x15,");

   Alias::addAlias("eq,", "0x0,");
   Alias::addAlias("ne,", "0x1,");
   Alias::addAlias("cs,", "0x2,");
   Alias::addAlias("hs,", "0x2,");
   Alias::addAlias("cc,", "0x3,");
   Alias::addAlias("lo,", "0x3,");
   Alias::addAlias("mi,", "0x4,");
   Alias::addAlias("pl,", "0x5,");
   Alias::addAlias("vs,", "0x6,");
   Alias::addAlias("vc,", "0x7,");
   Alias::addAlias("hi,", "0x8,");
   Alias::addAlias("ls,", "0x9,");
   Alias::addAlias("ge,", "0xa,");
   Alias::addAlias("lt,", "0xb,");
   Alias::addAlias("gt,", "0xc,");
   Alias::addAlias("le,", "0xd,");
   Alias::addAlias("al,", "0xe,");
   Alias::addAlias("nv,", "0xf,");
   
   Alias::addAlias("wzr,", "zr,");
   Alias::addAlias("wzr", "zr");
   Alias::addAlias("xzr,", "zr,");
   Alias::addAlias("xzr", "zr");
   */

       return 0;
}
