
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

#include "MappedInst.h"

#ifndef CONSECUTIVE_UNUSED_THRESHOLD
#define CONSECUTIVE_UNUSED_THRESHOLD 8
#endif

int getBitTypeByChanges(FieldList* startFields, char* dec_str);
int cmpBitTypes(BitType* t1, BitType* t2, unsigned int len);
void setInstructionBitVector(char* bytes, int* switchBits, int nSwitchBits, int i);
void printBitTypes(BitType* bitTypes, unsigned int nBits);

std::ostream& operator<<(std::ostream& s, MappedInst& m){
   FieldList* t = m.getFields();
   for (size_t i = 0; i < t->size(); i++) {
      if (i != 0) {
         s << " ";
      }
      s << t->getField(i);
   }
   return s;
}

bool MappedInst::isFirstByteRemovablePrefix() {
    
    char startBuf[DECODING_BUFFER_SIZE];
    char* startStr = &startBuf[0];
    
    char newBuf[DECODING_BUFFER_SIZE];
    char* newStr = &newBuf[0];
   
    bool success = !decoder->decode(bytes,
                                    nBytes,
                                    startStr, 
                                    DECODING_BUFFER_SIZE);
    
    if (!success) {
        return false;
    }

    if (norm) {
        decoder->normalize(startStr, DECODING_BUFFER_SIZE);
    }

    success = !decoder->decode(bytes + 1,
                               nBytes - 1,
                               newStr, 
                               DECODING_BUFFER_SIZE);

    if (!success) {
        return false;
    }

    if (norm) {
        decoder->normalize(newStr, DECODING_BUFFER_SIZE);
    }

    if (!strcmp(startStr, newStr)) {
        //std::cout << "FOUND UNPRINTED PREFIX!\n";
        return true;
    }

    while (*startStr && !isspace(*startStr)) {
        startStr++;
    }
    if (!*startStr) {
        return false;
    }
    startStr++;
   
    if (!strcmp(startStr, newStr)) {
        //std::cout << "FOUND REMOVABLE PREFIX IN:\n"; 
        //std::cout << "\t" << &startBuf[0] << "\n";
        //std::cout << "\t" << newStr << "\n";
        return true;
    }

    return false;

}

void MappedInst::deleteRemovablePrefixes() {
    char* baseBytes = bytes;
    while (isFirstByteRemovablePrefix()) {
        bytes++;
        nBytes--;
    }
    if (bytes == baseBytes) {
        return;
    }

    char* newStartBytes = bytes;
    bytes = (char*)malloc(nBytes);
    assert(bytes != NULL);
    
    memcpy(bytes, newStartBytes, nBytes);
    free(baseBytes);
}
   
void MappedInst::enqueueInsnIfNew(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc) {
  
    char oldNBytes = nBytes;
    char oldBytes[nBytes];
    memcpy(oldBytes, bytes, nBytes);
    deleteRemovablePrefixes();

    char decBuf[DECODING_BUFFER_SIZE];
    char* decStr = &decBuf[0];

    bool success = !decoder->decode(bytes,
                                    nBytes,
                                    decStr, 
                                    DECODING_BUFFER_SIZE);
    if (norm) {
        decoder->normalize(decStr, DECODING_BUFFER_SIZE);
    }

    if (success) {
        FieldList tList(decStr);
        if (!tList.hasError()) {
            tList.stripHex();
            tList.stripDigits();
            int len = tList.getTotalBytes() + 64;
            char* hcString = (char*)malloc(len);
            assert(hcString != NULL);

            tList.fillBuf(hcString, len);

            Architecture::replaceRegSets(hcString, len);

            if (hc->insert(std::make_pair(hcString, 1)).second) {
             
                std::cout << decoder->getName() << " queue: " << hcString 
                        << "\n";
                char* queuedBytes = (char*)malloc(nBytes);
                bcopy(bytes, queuedBytes, nBytes);
                queue->push(queuedBytes);
            } else {
                free(hcString);
            }
        }
    }
    
    nBytes = oldNBytes;
    free(bytes);
    bytes = (char*)malloc(nBytes);
    assert(bytes != NULL);
    memcpy(bytes, oldBytes, nBytes);
}

void MappedInst::queueNewInsns(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc) {
   
   int nBits = 8 * nBytes;

   for (int i = 0; i < nBits; i++) {

      if (bitTypes[i] != BIT_TYPE_SWITCH) {
         continue;
      }

      assert(8 * nBytes == (unsigned int)nBits);

      flipBufferBit(bytes, i);
      for (int j = i + 1; j < nBits; j++) {
         if (bitTypes[j] != BIT_TYPE_SWITCH) {
            continue;
         }
         flipBufferBit(bytes, j);
         enqueueInsnIfNew(queue, hc);
         flipBufferBit(bytes, j);
      }

      enqueueInsnIfNew(queue, hc);
      //printf("%s %d\n", decStr, bitTypes[i]);
      flipBufferBit(bytes, i);
   }
  
   return;
}

MappedInst::MappedInst(char* bytes, unsigned int nBytes, Decoder* dec, bool normalize) {

   char* decodedInstruction = (char*)malloc(DECODING_BUFFER_SIZE);
   assert(decodedInstruction != NULL);

   decoder = dec;
   int success = !decoder->decode(bytes, 
                                  nBytes, 
                                  decodedInstruction, 
                                  DECODING_BUFFER_SIZE);
   if (!success) {
      this->isError = true;
   } else {
      isError = false;
   }

   this->norm = normalize;
   if (this->norm) {
      decoder->normalize(decodedInstruction, DECODING_BUFFER_SIZE);
   }

   this->nBytes = nBytes;
   this->bitTypes = (BitType*)malloc(8 * nBytes * sizeof(BitType));
   this->bytes = (char*)malloc(nBytes);
   this->confirmed = (bool*)malloc(8 * nBytes * sizeof(bool));
  
   assert(bitTypes != NULL && bytes != NULL && confirmed != NULL);

   for (size_t i = 0; i < 8 * nBytes; i++) {
      confirmed[i] = false;
   }

   for (unsigned int i = 0; i < nBytes; i++) {
      this->bytes[i] = bytes[i];
   }
   
   fields = new FieldList(decodedInstruction);
   this->map();

   free(decodedInstruction);
}

MappedInst::~MappedInst() {
   delete fields;
   free(bytes);
   free(bitTypes);
   free(confirmed);
}

int MappedInst::getNumUsedBytes() {
   int nUsed = nBytes;
   for (int i = 8 * nBytes - 1; bitTypes[i] == BIT_TYPE_UNUSED && i >= 0; i--) {
      if (i % 8 == 0) {
          nUsed--;
      }
   }
   return nUsed;
}

void MappedInst::print() {
   for (size_t i = 0; i < fields->size(); i++) {
      printf("%s ", fields->getField(i));
   }
}

void MappedInst::map() {
   mapBitTypes(bitTypes);
}

FieldList* MappedInst::getFields() {
   return fields;
}

void MappedInst::makeSimpleMap(BitType* bTypes, FieldList* tkns) {
   int success = 0;
   size_t i = 0;
   unsigned int nBits = 8 * nBytes;
   char decStr[DECODING_BUFFER_SIZE];
   int consecutiveUnused = 0;

   
   std::vector<Bitfield*> bitfields;
   
   /*
   std::cout << "Mapping: ";
   for (i = 0; i < tkns->size(); i++) {
      std::cout << tkns->getField(i) << " ";
   }
   std::cout << "\n";

   
   std::cout << "Insn bits = " << "\n";
   for (j = 0; j < nBits; j++) {
      if (j % 8 == 0) {
         std::cout << "\n\t";
      }
      std::cout << (int)getBufferBit(bytes, j) << " ";
   }
   std::cout << "\n\n";
   */

   for (i = 0; i < tkns->size(); i++) {
      bitfields.push_back(Bitfield::create(tkns->getField(i), NULL));
   }

   // Iterate over each bit, flipping it. Update the bit types with each 
   // test. This is a first pass over the data. This will be a first pass
   // at the instruction. The second pass will try to identify operand
   // switches that don't alter multiple operands at once.
   for (i = 0; consecutiveUnused < CONSECUTIVE_UNUSED_THRESHOLD && i < nBits; i++) {
      flipBufferBit(bytes, i);
        
      success = !decoder->decode(bytes, nBytes, decStr, DECODING_BUFFER_SIZE);

      if (norm) {
         decoder->normalize(decStr, DECODING_BUFFER_SIZE);
      }

      // Default the bit type to unused.
      bTypes[i] = BIT_TYPE_UNUSED;
      if (success) {
         bTypes[i] = getBitTypeByChanges(tkns, decStr);

         //std::cout << decStr << " // BitTypes[" << i << "] = " << bTypes[i] << "\n";

         if (bTypes[i] >= 0) {

            Bitfield* bf = bitfields[bTypes[i]];
            if (bf != NULL) {
   

               flipBufferBit(bytes, i); 

               if (bf->matches(bytes, i, nBits)) {
                  flipBufferBit(bytes, i);
                  
                  //std::cout << "Found bitfield!\n";

                  confirmed[i] = true;
                  for (int j = 1; j < bf->size(); j++) {
                     confirmed[i + j] = true;
                     bTypes[i + j] = bTypes[i];
                  }

                  i += bf->size() - 1;
               } else {
                  flipBufferBit(bytes, i);
               }
            }
         }
                     
      } else {
         if (isError) {
            bTypes[i] = BIT_TYPE_UNUSED;
         } else {
            bTypes[i] = BIT_TYPE_CAUSED_ERROR;
         }
         //std::cout << decStr << " // BitTypes[" << i << "] = " << bTypes[i] << "\n";
      }

      consecutiveUnused++;
      if (bTypes[i] != BIT_TYPE_UNUSED) {
         consecutiveUnused = 0;
      }

      //printf("%s %d\n", decStr, bitTypes[i]);
      flipBufferBit(bytes, i);
   }

   // If we didn't make it to the end of the string, it was unused, so mark all
   // remaining bits unused.
   while (i < nBits) {
      bTypes[i] = BIT_TYPE_UNUSED;
      i++;
   }

   // Get rid of the bitfields.
   while(bitfields.size() > 0) {
      Bitfield* bf = bitfields.back();
      if (bf != NULL) {
         delete bf;
      }
      bitfields.pop_back();
   }
}

/*
int MappedInst::findOperandValue(BitType* bitTypes, char* val, int operandNum, int bitCount) {
   
   int nBits = nBytes * 8;
   int i = 0;

   while (i < nBits) {

      // Skip over a section of bit types not equal to the operand we are
      // trying to find.
      while (i < nBits && bitTypes[i] != operandNum) {
         i++;
      }
      int start = i;
      int end = i;
      while (end < nBits && bitTypes[end] == operandNum) {
         end++;
      }

      while (end - i + 1 >= bitCount && bitTypes[i] == operandNum) {
         int j = 0;

         // We have started a section of this bit type, so try to match it.
         while (i < nBits && bitTypes[i] == operandNum &&
               getBufferBit(bytes, i) == getBufferBit(val, j) &&
               j < bitCount) {

            j++;
            i++;
         }

         if (j == bitCount) {
            return i - bitCount - 1;
         } else {
            i++;
         }
      }

      if (end - i + 1 < bitCount) {
         i = end + 1;
      }


   }

   return -1;
}

void MappedInst::confirmHexOperand(BitType* bitTypes, char* operand, int operandNum) {
   
   long hexVal;
   bool hexFound = false;
   char* cur = operand;

   while (*cur && *cur != ' ' && !hexFound) {
      if (*cur == '0' && *(cur + 1) == 'x') {

         hexFound = true;
         if (cur != operand && *(cur - 1) == '-') {
            hexVal = strtol(cur - 1, NULL, 16);
         } else {
            hexVal = strtol(cur, NULL, 16);
         }
      } else {
         cur++;
      }
   }

   if (!hexFound) {
      return;
   }
  
   int operandBitCount = getMinBits(hexVal);

   char* valBuf = (char*)malloc(sizeof(long));
   for (int i = 0; i < 8; i++) {
      for (int j = 7; j >= 0; j--) {
         setBufferBit(valBuf, i * 8 + j, hexVal & 0x01);
         hexVal = hexVal >> 1;
      }
   }
   
   // We now have the value of the operand and a map, so we should be able to
   // match these up fairly well and save some time.
   
   int firstBit = findOperandValue(bitTypes, valBuf, operandNum, operandBitCount);

   if (firstBit < 0) {
      free(valBuf);
      return;
   }

   for (int i = firstBit; i < operandBitCount; i++) {
      confirmed[i] = true;
   }

   free(valBuf);

}

void MappedInst::confirmHexBits(BitType* bitTypes, char* decInsn) {

   char* cur = decInsn;
   int operandNum = 0;

   while (*cur) {
      while (*cur && *cur != ' ') {
         cur++;
      }
      
      if (*cur) {
         operandNum++;
         cur++;
         confirmHexOperand(bitTypes, cur, operandNum);
      }
   }

}
*/

void MappedInst::mapBitTypes(BitType* bitTypes) {
   size_t i = 0;
   unsigned int nBits = 8 * nBytes;
   char decStr[DECODING_BUFFER_SIZE];
   
   BitType* tmpBitTypes = (BitType*)malloc(nBits * sizeof(BitType));
   BitType* newBitTypes = (BitType*)malloc(nBits * sizeof(BitType));
   
   if (tmpBitTypes == NULL || newBitTypes == NULL) {
      throw "ERROR: Could not allocate bit type vector!\n";
   }

   makeSimpleMap(bitTypes, fields);
   
   // Next, iterate over every bit and select those which previously
   // altered one operand but not multiple. To determine if the bit is an
   // operand switch, remake the bit type vector and check if the size of
   // an operand has changed. If the size has changed, this is an operand
   // switch bit.
   for (i = 0; i < nBits; i++) {

      if (bitTypes[i] == BIT_TYPE_UNUSED ||
        //bitTypes[i] == BIT_TYPE_CAUSED_ERROR ||
          bitTypes[i] == BIT_TYPE_SWITCH ||
          confirmed[i]) {
      
         // This bit didn't change any operands or has already been
         // flagged as a switch, so ignore it and go to the next iteration
         newBitTypes[i] = bitTypes[i];
         continue;
      }

      // We've got a bit flagged for changing only one operand. We'll test
      // to see if it changes the number of bits that affect the operand,
      // or if it just changes the value of the current operand.
      flipBufferBit(bytes, i);

      decoder->decode(
         bytes,
         nBytes,
         decStr, 
         DECODING_BUFFER_SIZE
      );
      //printf("%s %d\n", decStr, bitTypes[i]);
      
      if (norm) {
         decoder->normalize(decStr, DECODING_BUFFER_SIZE);
      }
     
      FieldList* tList = new FieldList(decStr);
      makeSimpleMap(tmpBitTypes, tList);
      delete tList;

      bool matchesOldMapping = true;
      for (size_t k = 0; matchesOldMapping && k < nBits; k++) {
         if (tmpBitTypes[k] != bitTypes[k]) {
            if (tmpBitTypes[k] == BIT_TYPE_SWITCH && bitTypes[k] == BIT_TYPE_CAUSED_ERROR) {
            } else if (tmpBitTypes[k] == BIT_TYPE_CAUSED_ERROR &&
               bitTypes[k] == BIT_TYPE_SWITCH) {
            } else if (isError && bitTypes[k] == BIT_TYPE_SWITCH &&
               tmpBitTypes[k] == BIT_TYPE_UNUSED) {
            } else if (isError && bitTypes[k] == BIT_TYPE_UNUSED &&
               tmpBitTypes[k] == BIT_TYPE_SWITCH) {
            } else {
               matchesOldMapping = false;
            }
         }
      }

      if (matchesOldMapping) {
         newBitTypes[i] = bitTypes[i];
      } else {
         newBitTypes[i] = BIT_TYPE_SWITCH;
      }

      flipBufferBit(bytes, i);
   }

   memcpy(bitTypes, newBitTypes, nBits * sizeof(BitType));
   free(newBitTypes);
   free(tmpBitTypes);

}

int getBitTypeByChanges(FieldList* startFields, char* decStr) {
   BitType result = BIT_TYPE_UNUSED;
   FieldList fields(decStr);
   
   if (fields.size() != startFields->size()) {
      result = BIT_TYPE_SWITCH;
   } else {
            
      // We have the same operator, so we can continue looking at
      // operands.
      for (unsigned int i = 0; i < fields.size(); i++) {
         if (strcmp(fields.getField(i), startFields->getField(i))) {

            // If the bit hasn't caused a change so far, it may only be a part
            // of this operand. If it has changed one already, it's a switch.
            if (result == BIT_TYPE_UNUSED) {
               result = i;
            } else {
               result = BIT_TYPE_SWITCH;
            }
         }
      }
   }
   return result;
}

void setInstructionBitVector(char* inst, int* bitPositions, unsigned int nBit, int value) {
   for (unsigned int i = nBit - 1; i >= 0; i--) {
      setBufferBit(inst, bitPositions[i], value & 0x01);
      value = value >> 1;
   }
}

int cmpBitTypes(BitType* t1, BitType* t2, unsigned int len) {
   BitType* end = t1 + len;
   while (t1 < end) {
      if (*t1 != *t2) {
         return t1 - t2;
      }
      t1++;
      t2++;
   }
   return 0;
}

void printBitTypes(BitType* bitTypes, int nBits) {
   int i;
   for (i = 0; i < nBits; i++) {
      printf("%d", (int)bitTypes[i]);
   }
   printf("\n");
}

