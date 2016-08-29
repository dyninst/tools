
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

#include "aarch64_common.h"

void negCond(char* dest, char* src) {
    if (!strncmp(src, "al", 2)) {
        strncpy(dest, "nv", 2);
    } else if (!strncmp(src, "nv", 2)) {
        strncpy(dest, "al", 2);
    }
}

void aliasCsInsns(char* buf, int bufLen) {
    
    bool inv = !strncmp(buf, "csinv", 5);
    bool inc = !strncmp(buf, "csinc", 5);
    bool neg = !strncmp(buf, "csneg", 5);

    // This isn't one of the opcodes we want to deal with.
    if (!(inv || inc || neg)) {
        return;
    }

    char* operand1Start;
    char* operand2Start;
    char* operand3Start;
    char* operand4Start;

    char* cur = buf;
    while (*cur && *cur != ' ') {
        cur++; // Go to the end of the opcode.
    }
    if (!*cur) {
        return;
    }
    cur++;
    operand1Start = cur;
    while (*cur && *cur != ' ') {
        cur++; // Go to the end of the first operand.
    }
    if (!*cur) {
        return;
    }
    cur++;
    operand2Start = cur;
    while (*cur && *cur != ' ') {
        cur++; // Go to the end of the second operand.
    }
    if (!*cur) {
        return;
    }
    cur++;
    operand3Start = cur;
    while (*cur && *cur != ' ') {
        cur++; // Go to the end of the third operand.
    }
    if (!*cur) {
        return;
    }
    cur++;
    operand4Start = cur;

    // Only alias if condition code is "al"
    if (strncmp(operand4Start, "al", 2)) {
        return;
    }

    // Determine if operand 2 and 3 are the same (so we need to alias).
    if (strncmp(operand2Start, operand3Start, operand3Start - operand2Start)) {
        return; // Two operands were different, so we don't need to alias.
    }

    char* place = NULL;
   
    bool zeroRegs = !strncmp(operand2Start, "wzr", 3) || 
                    !strncmp(operand2Start, "xzr", 3);

    // The new opcode is cset if the operands are zero registers, otherwise, it
    // will be cinc.
    if (zeroRegs) {

        if (inc) {
            strncpy(buf, "cset", 4);
            place = buf + 4;
        } else if (inv) {
            strncpy(buf, "csetm", 5);
            place = buf + 5;
        } else {
            strncpy(buf, "cneg", 4);
            place = buf + 4;
        }
    } else {
        if (inc) {
            strncpy(buf, "cinc", 4);
            place = buf + 4;
        } else if (inv) {
            strncpy(buf, "cinv", 4);
            place = buf + 4;
        } else {
            strncpy(buf, "cneg", 4);
            place = buf + 4;
        }
    }

    // Add a space after the opcode.
    *place = ' ';
    place++;

    // Copy operands 1 and 2 over, leaving out operand 3. (leaving out 2 as
    // well if it was a zero register).
    //
    // Note: We can safely copy using a single buffer becase we know the new
    // opcode is shorter than the old one.
    int copyLen = operand3Start - operand1Start;
    if ((inv || inc) && zeroRegs) {
        copyLen = operand2Start - operand1Start;
    }
    char* copySrc = operand1Start;
    char* endPlace = place + copyLen;
    while (place < endPlace) {
        *place = *copySrc;
        place++;
        copySrc++;
    }

    // Negate the condition code. These codes are all 2 characters, hence the
    // two character offset of place.
    //
    // Note: We can safely place the new condition because we know that we
    // decreased instruction length, since an operand was left off.
    negCond(place, operand4Start);
    place += 2;
    *place = '\0';
}

void removeExtraZeroesFromFmovImm(char* buf, int bufLen) {
   
    // Verify that this is an fmov instruction.
    if (strncmp(buf, "fmov", 4)) {
        return;
    }

    // Get a pointer in the buffer to move around and analyze bytes.
    char* cur = buf;

    // Go until we find the end of the string (which includes the immediate).
    bool immVersion = false;
    int curField = 0;
    while(*cur) {
        if (*cur == ' ') {
            curField++;
            if (curField == 2 && isdigit(*(cur + 1))) {
                immVersion = true;
            }
        }
        cur++;
    }

    if (!immVersion) {
        return;
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
