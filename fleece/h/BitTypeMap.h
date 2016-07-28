
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

#ifndef _BIT_TYPE_MAP_H_
#define _BIT_TYPE_MAP_H_

#include <iostream>
#include <ios>
#include <iomanip>
#include <string.h>
#include "Mystring.h"
#include "MappedInst.h"
#include "BitTypes.h"

class BitTypeMap {

public:
   BitTypeMap(MappedInst* baseInst);
   BitTypeMap(BitTypeMap* toBeCopied);
   ~BitTypeMap(void);
   int addInst(MappedInst* inst);
   int combine(BitTypeMap* otherMap);
   bool canCombine(BitTypeMap* otherMap);
   bool doTypesMatch(MappedInst* inst);
   bool contains(MappedInst* inst);
   int compare(BitTypeMap* otherMap);
   unsigned long getBitTypeHash(void);
   std::vector<char*>* getKeys(void);
   BitType* getBitTypes(void);
   unsigned int getNumBits(void);
   unsigned int getKeySize(void) { return keySize; }
   unsigned int getNUsedBytes(void);
   void fuzzDecoders(Decoder* d1, Decoder* d2);

private:

   bool hasKey(char* key);
   void getInstKey(MappedInst* inst, char* blankKey);
   void recurTestKeyBit(Decoder* d1, Decoder* d2, unsigned int whichBit, char* curBuf);

   BitType* bitTypes;
   unsigned int nBits;
   unsigned int nUsedBytes;
   unsigned int nSwitchBits;
   unsigned int nErrorBits;
   unsigned int keySize;
   unsigned int keyBitSize;
   std::vector<char*> instKeys;

};

std::ostream& operator<<(std::ostream& s, BitTypeMap& b);

#endif // _BIT_TYPE_MAP_H_
