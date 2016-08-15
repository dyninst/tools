
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

#include "BitTypeMap.h"

unsigned int maxKeySize = 0;

BitTypeMap::BitTypeMap(MappedInst* baseInst) {
   nBits = 8 * baseInst->getNumBytes();
   nUsedBytes = baseInst->getNumUsedBytes();
   bitTypes = (BitType*)malloc(nBits * sizeof(BitType));

   if (bitTypes == NULL) {
      throw "malloc failed\n";
   }

   bcopy(baseInst->getBitTypes(), bitTypes, nBits * sizeof(BitType));

   nSwitchBits = 0;
   nErrorBits = 0;
   for (unsigned int i = 0; i < nBits; i++) {
      if (bitTypes[i] == BIT_TYPE_SWITCH) {
         nSwitchBits++;
      } else if (bitTypes[i] == BIT_TYPE_CAUSED_ERROR) {
         nErrorBits++;
      }
   }

   keyBitSize = nSwitchBits + nErrorBits;
   keySize = (keyBitSize + 7) >> 3;
   if (keySize > maxKeySize) {
      maxKeySize = keySize;
   }

   char* key = (char*)malloc(keySize);
   if (key == NULL) {
      throw "malloc failed\n";
   }
   getInstKey(baseInst, key);
   instKeys.push_back(key);
}

BitTypeMap::~BitTypeMap() {
   std::vector<char*>::iterator it;
   for (it = instKeys.begin(); it != instKeys.end(); it++) {
      free(*it);
   }
   free(bitTypes);
}

BitTypeMap::BitTypeMap(BitTypeMap* toBeCopied) {
   nBits = toBeCopied->nBits;
   bitTypes = (BitType*)malloc(nBits * sizeof(BitType));

   if (bitTypes == NULL) {
      throw "malloc failed\n";
   }

   bcopy(toBeCopied->getBitTypes(), bitTypes, nBits * sizeof(BitType));

   nUsedBytes = toBeCopied->nUsedBytes;
   nSwitchBits = toBeCopied->nSwitchBits;
   nErrorBits = toBeCopied->nErrorBits;
   keySize = toBeCopied->keySize;

   std::vector<char*> otherKeys = toBeCopied->instKeys;
   for (unsigned int i = 0; i < otherKeys.size(); i++) {      
      char* key = (char*)malloc(keySize);
      if (key == NULL) {
         throw "malloc failed\n";
      }
      bcopy(otherKeys[i], key, keySize);
      instKeys.push_back(key);
   }
}


int BitTypeMap::addInst(MappedInst* inst) {
   if (!doTypesMatch(inst)) {
      return -1;
   }

   if (contains(inst)) {
      return -1;
   }

   char* key = (char*)malloc(keySize);
   if (key == NULL) {
      throw "malloc failed\n";
   }
   getInstKey(inst, key);
   instKeys.push_back(key);
   return 0;
}

int BitTypeMap::combine(BitTypeMap* otherMap) {
   if (!canCombine(otherMap)) {
      return -1;
   }
   
   std::vector<char*> otherKeys = otherMap->instKeys;
   for (unsigned int i = 0; i < otherKeys.size(); i++) {
      if (!hasKey(otherKeys[i])) {
         char* keyCopy = (char*)malloc(keySize);
         if (keyCopy == NULL) {
            throw "malloc failed\n";
         }
         bcopy(otherKeys[i], keyCopy, keySize);
         instKeys.push_back(keyCopy);
      }
   }

   return 0;
}

bool BitTypeMap::canCombine(BitTypeMap* otherMap) {
   return compare(otherMap) == 0;
}

bool BitTypeMap::doTypesMatch(MappedInst* inst) {
   
   if (inst->getNumBytes() * 8 != nBits) {
      return false;
   }

   size_t numUsedBytes = inst->getNumUsedBytes();

   if (numUsedBytes != nUsedBytes) {
      return false;
   }

   BitType* instBitTypes = inst->getBitTypes();
   for (unsigned int i = 0; i < 8 * nUsedBytes; i++) {
      if (instBitTypes[i] != bitTypes[i]) {
         return false;
      }
   }
   return true;
}

bool BitTypeMap::contains(MappedInst* inst) {
   if (!doTypesMatch(inst)) {
      return false;
   }

   char* key = (char*)malloc(keySize);
   getInstKey(inst, key);
   if (hasKey(key)) {
      free(key);
      return true;
   }

   free(key);
   return false;
}

int BitTypeMap::compare(BitTypeMap* otherMap) {
   if (otherMap->getNumBits() != nBits) {
      return nBits - otherMap->getNumBits();
   }
 
   BitType* otherBitTypes = otherMap->getBitTypes();
   for (unsigned int i = 0; i < nBits; i++) {
      if (otherBitTypes[i] != bitTypes[i]) {
         return bitTypes[i] - otherBitTypes[i];
      }
   }

   return 0;
}

unsigned long BitTypeMap::getBitTypeHash() {
   return hashBitTypes(bitTypes, nBits);
}

unsigned int BitTypeMap::getNUsedBytes() {
   return nUsedBytes;
}

void BitTypeMap::fuzzDecoders(Decoder* d1, Decoder* d2) {
   unsigned int i, j, curKeyIndex = 0;;
   unsigned int counts[MAX_OPERANDS];
   unsigned int curIndex[MAX_OPERANDS];

   for (i = 0; i < MAX_OPERANDS; i++) {
      counts[i] = 0;
      curIndex[i] = 0;
   }

   //std::cout << "Allocating key position vector!\n";
   unsigned int* keyPos = (unsigned int*)malloc(keyBitSize * sizeof(unsigned int));
   
   for (i = 0; i < 8 * nUsedBytes; i++) {
      if (bitTypes[i] == BIT_TYPE_CAUSED_ERROR || bitTypes[i] == BIT_TYPE_SWITCH)
      {
         keyPos[curKeyIndex] = i;
         curKeyIndex++;
      } else if (bitTypes[i] >= 0) {
         counts[bitTypes[i]]++;
      }
   }

   //std::cout << "Allocating token position vectors!\n";
   unsigned int** tokenPos = (unsigned int**)malloc(MAX_OPERANDS * sizeof(unsigned int *));
   
   for (i = 0; i < MAX_OPERANDS; i++) {
      if (counts[i] > 0) {
         //std::cout << "\tAllocating " << counts[i] << " ints for type " << i << std::endl;
         tokenPos[i] = (unsigned int*)malloc(counts[i] * sizeof(unsigned int));
      }
   }

   //std::cout << "Filling key position vector!\n";
   for (i = 0; i < 8 * nUsedBytes; i++) {
      if (bitTypes[i] >= 0) {
         //std::cout << "\tFound usable bit " << i << " (type = " << bitTypes[i] << ")!\n";
         int t = bitTypes[i]; 
         tokenPos[t][curIndex[t]] = i;
         curIndex[t]++;
      }
   }
   //exit(0);

   //std::cout << "Beginning decode loop!\n";
   char decodedBuf[1000];
   char* testInst = (char*)malloc(nBits /8);
   for (i = 0; i < instKeys.size(); i++) {
      randomizeBuffer(testInst, nBits / 8);
      setBufferBitVector(testInst, keyPos, instKeys[i], keyBitSize);
      
      //std::cout << "Analyzing key " << i << " of " << instKeys.size() << "!\n";
      for (j = 0; j < MAX_OPERANDS; j++) {
         if (counts[j] > 0) {
            randomizeBufferBitVector(testInst, tokenPos[j], counts[j]);
         }
      }
      int retval = d1->decode(testInst, nBits / 8, decodedBuf, 1000);
      
      if (retval == 0) {
         std::cout << decodedBuf << std::endl;
         for (size_t j = 0; j < nBits / 8; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                << (unsigned int)(unsigned char)testInst[j] << " ";
         }
      }
   }


   for (i = 0; i < MAX_OPERANDS; i++) {
      if (counts[i] > 0) {
         free(tokenPos[i]);
      }
   }

   free(tokenPos);
   free(keyPos);
}

// PRIVATE INTERFACE BELOW

void BitTypeMap::recurTestKeyBit(Decoder* d1, Decoder* d2, unsigned int whichBit, char* curBytes) {
   
   unsigned int nextBit = whichBit;
   while (nextBit < nBits && 
          bitTypes[nextBit] != BIT_TYPE_CAUSED_ERROR && 
          bitTypes[nextBit] != BIT_TYPE_SWITCH) {
      nextBit++;
   }
   
   if (nextBit == nBits) {
      setBufferBit(curBytes, whichBit, 0);
      // TODO: Implement comparison here!
      setBufferBit(curBytes, whichBit, 0);
      // TODO: Compare here too!
   } else {
      setBufferBit(curBytes, whichBit, 0);
      recurTestKeyBit(d1, d2, nextBit, curBytes);
      setBufferBit(curBytes, whichBit, 1);
      recurTestKeyBit(d1, d2, nextBit, curBytes);
   }
}

bool BitTypeMap::hasKey(char* key) {
   for (unsigned int k = 0; k < instKeys.size(); k++) {
      bool match = true;
      for (unsigned int i = 0; match && i < keySize; i++) {
         if (instKeys[k][i] != key[i]) {
            match = false;
         }
      }
      if (match) {
         return true;
      }
   }
   return false;
}

void BitTypeMap::getInstKey(MappedInst* inst, char* blankKey) {
   unsigned int curBit = 0;
   for (unsigned int i = 0; i < nBits; i++) {
      if (bitTypes[i] == BIT_TYPE_CAUSED_ERROR ||
          bitTypes[i] == BIT_TYPE_SWITCH) {

         //std::cout << "Bit " << i << " = " << (1 & getBufferBit(inst->getRawBytes(), i)) << std::endl;
         setBufferBit(blankKey, curBit, getBufferBit(inst->getRawBytes(), i));
         curBit++;
      }
   }
}

BitType* BitTypeMap::getBitTypes() {
   return bitTypes;
}

unsigned int BitTypeMap::getNumBits() {
   return nBits;
}

std::vector<char*>* BitTypeMap::getKeys() {
   return &instKeys;
}

unsigned int nKeys = 0;

std::ostream& operator<<(std::ostream& s, BitTypeMap& b) {
   //nKeys = 0;
   BitType* bitTypes = b.getBitTypes();
   unsigned int keySize = b.getKeySize();
   std::vector<char*>* instKeys = b.getKeys();
   for (unsigned int i = 0; i < 8 * b.getNUsedBytes(); i++) {
      if (i % 8 == 0) {
         s << std::endl;
      }
      s << std::setfill(' ') << std::setw(2) << (int)bitTypes[i] << " ";
   }
   s << std::endl << "Keys:" << std::endl;
   for (unsigned int i = 0; i < instKeys->size(); i++) {
      nKeys++;
      for (unsigned int j = 0; j < keySize; j++) {
         s << std::hex << std::setfill('0') << std::setw(2) <<
            (unsigned int)(unsigned char)((*instKeys)[i][j]);
      }
   s << std::dec << std::endl;
   }
   s << "Total Key Count: " << nKeys << std::endl;
   return s;
}
