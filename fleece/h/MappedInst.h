
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

#ifndef _MAPPEDINST_H_
#define _MAPPEDINST_H_

#include "Bitfield.h"
#include "Architecture.h"
#include "Decoder.h"
#include "Mystring.h"
#include "hashtable.h"
#include "Hashcounter.h"
#include <queue>
#include "BitTypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>

class Decoder;

class MappedInst {
public:
   MappedInst(char* bytes, unsigned int nBytes, Decoder* dec, bool normalize);
   ~MappedInst();
   int getNumUsedBytes();
   void print();
   TokenList* getTokens();
   BitType*     getBitTypes() {return bitTypes;}
   unsigned int getNumBytes() {return nBytes;  }
   char*        getRawBytes() {return bytes;   }
   unsigned long getBitTypeHash() {return hashBitTypes(bitTypes, 8 * nBytes);}
   void queueNewInsns(std::queue<char*>* queue, Hashcounter* hc);

private:
   bool* confirmed;
   char* bytes;
   unsigned int nBytes;
   bool isError;
   bool norm;
   BitType* bitTypes;
   TokenList* tokens;
   Decoder* decoder;
   void map(void);
   void mapBitTypes(BitType* bitTypes);
   void makeSimpleMap(BitType* bTypes, TokenList* tokens);
   //int findOperandValue(BitType* bitTypes, char* val, int operandNum, int bitCount);
   //void confirmHexOperand(BitType* bitTypes, char* operand, int operandNum);
   //void confirmHexBits(BitType* bitTypes, char* decInsn);
   void enqueueInsnIfNew(std::queue<char*>* queue, Hashcounter* hc);
};

std::ostream& operator<<(std::ostream& s, MappedInst& m);

#endif /* _MAPPEDINST_H_ */
