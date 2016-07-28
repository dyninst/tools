
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

#include "Bitfield.h"

Bitfield* Bitfield::create(char* str, char** endPtr) {
   
   long hexVal;
   bool hexFound = false;
   char* cur = str;

   while (*cur && *cur != ' ' && !hexFound) {
      if (*cur == '0' && *(cur + 1) == 'x') {

         hexFound = true;
         if (cur != str && *(cur - 1) == '-') {
            hexVal = strtol(cur - 1, endPtr, 16);
         } else {
            hexVal = strtol(cur, endPtr, 16);
         }
      } else {
         cur++;
      }
   }

   if (!hexFound) {
      if (endPtr != NULL) {
         *endPtr = cur;
      }
      return NULL;
   }

   int nBits = getMinBits(hexVal);
   int nBytes = (nBits + 7) / 8;

   char* valBuf = (char*)malloc(nBytes);
   assert(valBuf != NULL);
   for (int i = 0; i < nBytes; i++) {
      for (int j = 7; j >= 0; j--) {
         setBufferBit(valBuf, i * 8 + j, hexVal & 0x01);
         hexVal = hexVal >> 1;
      }
   }

   return new Bitfield(valBuf, nBits);
}  


Bitfield::Bitfield(char* buf, int size) {
   bytes = buf;
   sz = size;
}


Bitfield::~Bitfield() {
   free(bytes);
}

int Bitfield::getBit(int bit) {
   return getBufferBit(bytes, bit);
}

bool Bitfield::matches(char* buf, int whichBit, int nBits) {
   
   int i;

   for (i = 0; i < sz && whichBit + i < nBits; i++) {
      if (getBufferBit(buf, whichBit + i) != getBufferBit(bytes, i)) {
         return false;
      }
   }

   if (whichBit + i == nBits && i != sz) {
      return false;
   }
  
   return true;
}

int Bitfield::size() {
   return sz;
}
