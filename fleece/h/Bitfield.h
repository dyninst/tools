
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

#ifndef _BITFIELD_H_
#define _BITFIELD_H_

#include "Mystring.h"

class Bitfield {
public:
   static Bitfield* create(char* str, char** endptr);
   ~Bitfield();
   bool matches(char* buf, int whichBit, int nBits);
   int size();
   int getBit(int bit);
private:
   Bitfield(char* buf, int size);
   char* bytes;
   int sz; // size in bits.
};

#endif // _BITFIELD_H_
