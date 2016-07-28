
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

#include "Normalization.h"
#include "Mystring.h"
#include <iostream>
#include <iomanip>
#include "llvm_common.h"
#include <sys/mman.h>

using namespace llvm;

void trimBraceSpaces(char* buf, int bufLen) {
   char* cur = buf;
   char* place = buf;
   while (*cur) {
      if (*cur == '{' && *(cur + 1) == ' ') {
         *place = *cur;
         place++;
         cur++;
      } else if (!(*cur == ' ' && *(cur + 1) == '}')) {
         *place = *cur;
         place++;
      }
      cur++;
   }
   *place = 0;
}

char negHex(char h) {
   
   if (h >= '0' && h <= '5') {
      return 'f' + '0' - h;
   }

   if (h >= '6' && h <= '9') {
      return '9' + '6' - h;
   }

   if (h >= 'a' && h <= 'f') {
      return 'f' + '0' - h;
   }

   return h;
}

void aliasMovn(char* buf, int bufLen) {
   if (strncmp(buf, "movn", 4)) {
      return;
   }

   char* tmp = (char*)malloc(bufLen);
   assert(tmp != NULL);

   // We have a movz instruction, so delete the z.
   char* cur = buf;
   char* place = tmp;

   for(int i = 0; i < 3; i++) {
      *place = *cur;
      place++;
      cur++;
   }

   cur++;
   bool wide = *(cur + 1) == 'x';
   
   // Copy until the immediate field.
   while(*cur && *(cur - 4) != ',') {
      *place = *cur;
      place++;
      cur++;
   }

   int nDigits = 0;
   
   while (*cur && *cur != ',') {
      nDigits++;
      cur++;
   }
   
   int nFs = 0;
   if (*cur != 0) {
      nFs = 4 * (*(cur + 8) - '0');
   }
   cur -= nDigits;

   // If we have all 4 digits but the first doesn't have a proper sign, put it
   // there.
   if ((nDigits < 4 || (!wide && nFs == 0) || (wide && nFs < 12)) && 
         negHex(*cur) < '8' && negHex(*cur) >= '0') {
      *place = 'f';
      place++;
   }

   // Copy over the negated hex digits from the string.
   for (int i = 0; i < nDigits; i++) {
      *place = negHex(*cur);
      place++;
      cur++;
   }

   for (int i = 0; i < nFs; i++) {
      *place = 'f';
      place++;
   }
   *place = 0;

   strcpy(buf, tmp);
   free(tmp);
}

void aliasMovz(char* buf, int bufLen) {
   if (strncmp(buf, "movz", 4)) {
      return;
   }

   // We have a movz instruction, so delete the z.
   char* cur = buf + 4;
   int nCommas = 0;
   while (*cur) {
      if (*cur == ',') {
         nCommas++;
      }
      *(cur - 1) = *cur;
      cur++;
   }
   cur--;
   *cur = 0;

   // If we only ran into 1 comma, there wasn't a shift left term, so we are
   // done already.
   if (nCommas == 1) {
      return;
   }

   cur -= 2;
   int nZeroes = 4 * (*cur - '0');
   
   while (*cur != ',') {
      cur--;
   }

   for (int i = 0; i < nZeroes; i++) {
      *cur = '0';
      cur++;
   }
   *cur = 0;
}

void removeExtraZeroesFromFmovImm(char* buf, int bufLen) {
   
   // Verify that this is an fmov instruction.
   if (strncmp(buf, "fmov", 4)) {
      return;
   }

   // Get a pointer in the buffer to move around and analyze bytes.
   char* cur = buf;

   // Go until we find the end of the string (which includes the immediate).
   while(*cur) {
      cur++;
   }
   cur--;

   // Walk back to the decimal point, removing zeroes along the way.
   bool inZeroes = true;
   while (cur > buf && *cur != '.') {
      if (*cur == '0' && inZeroes) {
         *cur = 0;
      } else {
         inZeroes = false;
      }
      cur--;
   }

   // If we read only zeroes all the way to the decimal point, remove the
   // decimal point as well.
   if (inZeroes) {
      *cur = 0;
   }

   // We hit the beginning of the buffer without a decimal point, so stop.
   if (cur == buf) {
      return;
   }

   // We need to see if the immediate value had a leading zero too, so back up.
   cur--;

   // If there isn't a zero, we know we're done already.
   if (*cur != '0') {
      return;
   }
   
   if (*(cur - 1) == ' ' || (*(cur - 1) == '-' && *(cur - 2) == ' ')) {

      while (*(cur + 1)) {
         *cur = *(cur + 1);
         cur++;
      }

      *cur = 0;
   }

}

static const char* LLVMCallback(void* info, uint64_t refVal, uint64_t* refType, uint64_t refPC, const char** refName) {

   *refType = LLVMDisassembler_ReferenceType_InOut_None;
   return nullptr;

}

int llvm_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {

   static LLVMDisasmContextRef disasm = LLVMCreateDisasm("aarch64-linux-gnu", nullptr, 0, nullptr, LLVMCallback);

   size_t bytesUsed = LLVMDisasmInstruction(disasm, (uint8_t*)inst, nBytes, 0, buf, (size_t)bufLen);

   if (!bytesUsed) {
      strncpy(buf, "llvm_decoding_error", bufLen);
   }

   return !bytesUsed;
}

void llvm_aarch64_norm(char* buf, int bufLen) {

   // NORMALIZATION STEPS

   cleanSpaces(buf, bufLen);
   //removeCharacter(buf, bufLen, ']');
   //removeCharacter(buf, bufLen, '[');
   removeComments(buf, bufLen);
   toLowerCase(buf, bufLen);
   decToHexConstants(buf, bufLen);
   removePounds(buf, bufLen);
   trimBraceSpaces(buf, bufLen);
   aliasMovz(buf, bufLen);
   aliasMovn(buf, bufLen);
   trimHexFs(buf, bufLen);
   trimHexZeroes(buf, bufLen);
   removeExtraZeroesFromFmovImm(buf, bufLen);
}

