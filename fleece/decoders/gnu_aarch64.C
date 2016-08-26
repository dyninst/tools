
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

void changeBcsToBhs(char* buf, int bufLen) {
   char* cur = buf;

   if (bufLen > 4 && 
       *cur       == 'b' && 
       *(cur + 1) == '.' && 
       *(cur + 2) == 'c' && 
       *(cur + 3) == 's' && 
       *(cur + 4) == ' ') {

      *(cur + 2) = 'h';
   }
}

void changeBccToBlo(char* buf, int bufLen) {
   char* cur = buf;

   if (bufLen > 4 && 
       *cur       == 'b' && 
       *(cur + 1) == '.' && 
       *(cur + 2) == 'c' && 
       *(cur + 3) == 'c' && 
       *(cur + 4) == ' ') {

      *(cur + 2) = 'l';
      *(cur + 3) = 'o';
   }
}

void changeCcToLo(char* buf, int bufLen) {
   char* cur = buf;
   while (*cur) {
      cur++;
   }
   
   // Make sure we aren't at the beginning of the buffer still.
   if (cur < buf + 4) {
      return;
   }

   if (*(cur - 1) == 'c' && 
       *(cur - 2) == 'c' &&
       *(cur - 3) == ' ') {

      *(cur - 2) = 'l';
      *(cur - 1) = 'o';
   }

}

void changeCsToHs(char* buf, int bufLen) {
   char* cur = buf;
   while (*cur) {
      cur++;
   }
   
   // Make sure we aren't at the beginning of the buffer still.
   if (cur < buf + 4) {
      return;
   }

   if (*(cur - 1) == 's' && 
       *(cur - 2) == 'c' &&
       *(cur - 3) == ' ') {

      *(cur - 2) = 'h';
   }

}

void fixRegLists(char* buf, int bufLen) {

   char* tmp = (char*)malloc(bufLen);

   char* cur = buf;
   char* place = tmp;

   while (*cur) {
      if (*cur == '{') {
         // We've found one of the trouble spots. Lets see if it's a range.
         char* check = cur;
         while (*check && *check != '}' && *check != '-') {
            check++;
         }

         if (*check == '-') {
            
            // Determine the ending appended to each register. This goes from
            // the '.' of the 2nd value to the '}' symbol.
            while (*check != '.') {
               check++;
            }
            char* ending = check;

            // Find the length of the ending so we can copy it correctly.
            while (*check != '}') {
               check++;
            }
            int endLen = check - ending;

            // We've got one with a range list instead of a set, so we need to
            // record the range and turn it into a set.
            int minReg = 0;
            int maxReg = 0;

            // First, find the number of the maximum register.
            while (*check != '.') {
               check--;
            }
            check--;

            // Now, we're at the actual maximum number, so record it.
            int factor = 1;

            while (*check != 'v') {
               maxReg += (*check - '0') * factor;
               factor *= 10;
               check--;
            }

            // Now, back up to the first number and record the minimum
            // register.
            while (*check != '.') {
               check--;
            }
            check--;

            factor = 1;

            while (*check != 'v') {
               minReg += (*check - '0') * factor;
               factor *= 10;
               check--;
            }

            strncpy(place, "{v", 2);
            place += 2;

            for (int i = minReg; i < maxReg; i++) {
               if (i > 9) {
                  *place = i / 10 + '0';
                  place++;
               }
               *place = i % 10 + '0';
               place++;
               strncpy(place, ending, endLen);
               place += endLen;

               strncpy(place, ", v", 3);
               place += 3;
            }

            if (maxReg > 9) {
               *place = maxReg / 10 + '0';
               place++;
            }
            *place = maxReg % 10 + '0';
            place++;
            strncpy(place, ending, endLen);
            place += endLen;

            *place = '}';
            place++;

            while (*cur != '}') {
               cur++;
            }

         } else {
            *place = *cur;
            place++;
         }
            
      } else {
         *place = *cur;
         place++;
      }
      cur++;
   }

   *place = 0;

   strncpy(buf, tmp, bufLen);

   free(tmp);
}

void changeFmovImm(char* buf, int bufLen) {
   
   // Verify that this is an fmov instruction.
   if (strncmp(buf, "fmov", 4)) {
      return;
   }
   
   // Get a pointer in the buffer to move around and analyze bytes.
   char* cur = buf;

   // Go until we find the 'e' sign of the exponent.
   while(*cur && *cur != 'e') {
      cur++;
   }

   // if we fell off the string, return.
   if (!*cur) {
      return;
   }

   // Put a null byte where this sign was, since we don't want to have the
   // power suffix anymore.
   *cur = 0;
   
   cur++;
   
   int swapPos = -1;
   if (*cur == '+') {
      swapPos = 1;
   }

   // The exponent always takes the form "e+0x" or "e-0x" where the x can only
   // be 0 or 1. If it is zero, we don't want to swap at the end, because the
   // number is already correct.
   if (*(cur + 2) == '0') {
      swapPos = 0;
   }

   // Put the current pointer at the end of the number.
   cur -= 2;

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

   // If we couldn't find a decimal point, we don't know what to do, so return.
   if (cur == buf) {
      return;
   }

   // If we saw only zeroes up to the decimal point, remove that too.
   if (inZeroes) {
      *cur = 0;

      // If we are swapping left, we would have put a leading zero, so don't
      // swap.
      if (swapPos == -1) {
         swapPos = 0;
      }
   }

   // We will use this to swap around positions.
   char tmp = *cur;
   *cur = *(cur + swapPos);
   *(cur + swapPos) = tmp;
   
   // If we swapped the decimal point to be the last value in the string, remove
   // it.
   if (*(cur + swapPos + 1) == 0) {
      *(cur + swapPos) = 0;
   }
}

int gnu_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {
     
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
   disInfo.arch = bfd_arch_aarch64;

   int rc = 0;

   rc = print_insn_aarch64((bfd_vma)0, &disInfo);

   fclose(outf);

   return !(rc > 0);
}

void gnu_aarch64_norm(char* buf, int bufLen) {
  
  // NORMALIZATION STEPS
    
   cleanSpaces(buf, bufLen);
   toLowerCase(buf, bufLen);
   spaceAfterCommas(buf, bufLen);
   //removeCharacter(buf, bufLen, '[');
   //removeCharacter(buf, bufLen, ']');
   removeComments(buf, bufLen);
   decToHexConstants(buf, bufLen);
   trimHexZeroes(buf, bufLen);
   trimHexFs(buf, bufLen);
   removePounds(buf, bufLen);
   removeADRPZeroes(buf, bufLen);
   fixRegLists(buf, bufLen);
   changeCsToHs(buf, bufLen);
   changeCcToLo(buf, bufLen);
   changeBccToBlo(buf, bufLen);
   changeBcsToBhs(buf, bufLen);
   changeFmovImm(buf, bufLen);

}
