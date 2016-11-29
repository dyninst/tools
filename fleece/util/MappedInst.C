
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

bool MappedInst::isByteOptional(size_t whichByte) {
    
    //std::cout << "testing byte " << whichByte << "\n";

    char newBuf[DECODING_BUFFER_SIZE];
    char* newStr = &newBuf[0];

    char newBytes[nBytes - 1];
    int j = 0;
    for (size_t i = 0; i < nBytes; i++) {
        if (i != whichByte) {
            newBytes[j] = bytes[i];
            j++;
        }
    }

    bool success = !decoder->decode(newBytes, nBytes - 1, newStr, 
            DECODING_BUFFER_SIZE);

    if (!success) {
        //std::cout << "Decoding failed, byte not optional\n";
        return false;
    }

    FieldList new_fields = FieldList(newStr);
    if (new_fields.hasError()) {
        //std::cout << "Decoding produced error, byte not optional\n";
        return false;
    }

    /*        
    std::cout << "Comparing isntructions:\n";
    std::cout << "new: " << newStr << "\n\tTO\n";
    fields->print(stdout);
    */

    for (size_t i = 0; i < new_fields.size(); i++) {
        const char* curField = new_fields.getField(i);
        bool foundField = true;
        if (!fields->hasField(curField)) {
            foundField = false;
            if (*curField == '0' && *(curField + 1) == 'x') {
                double d = atof(curField);
                for (size_t j = 0; j < fields->size(); j++) {
                     const char* oldField = fields->getField(j);
                     if (d == atof(oldField) - 1) {
                        foundField = true;
                     }
                }
            }
        }
        if (!foundField) {
            return false;
        }
    }

    //std::cout << "byte is optional!\n";
    return true;
}

void MappedInst::deleteOptionalBytes() {
    for (size_t i = 0; i < nBytes; i++) {
        if (isByteOptional(i)) {

            for (size_t j = i; j < nBytes - 1; j++) {
                bytes[j] = bytes[j + 1];
            }
            nBytes--;
            i--;
            char newBuf[DECODING_BUFFER_SIZE];
            char* newStr = &newBuf[0];
            decoder->decode(bytes, nBytes, newStr, DECODING_BUFFER_SIZE);
            delete fields;
            fields = new FieldList(newStr);

            //std::cout << "Byte " << i + 1 << " is optional.\n";
        }
    }
   
    /*
    std::cout << "Final bytes:\n\t";
    for (size_t j = 0; j < nBytes; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)bytes[j] << " ";
    }
    std::cout << "\n";
    exit(-1);
    */
}

void MappedInst::trimUnusedEnd() {
    
    char oldBuf[DECODING_BUFFER_SIZE];
    char* oldStr = &oldBuf[0];
    int success = !decoder->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE);

    if (!success) {
        return;
    }

    char newBuf[DECODING_BUFFER_SIZE];
    char* newStr = &newBuf[0];

    for (size_t i = 0; i < nBytes; i++) {
        int newSuc = !decoder->decode(bytes, i, newStr, DECODING_BUFFER_SIZE);
        if (newSuc && !strcmp(newStr, oldStr)) {
            nBytes = i;
            //std::cout << "|-- UNUSED TRIMMED (len = " << nBytes << ") --|\n";
            return;
        }
    }
}
   
void MappedInst::enqueueInsnIfNew(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc) {
    /*
    std::cout << "\n\n|---- BEGINNING QUEUEING ----|\n\n";
    std::cout << "Bytes before removal:\n";
    for (size_t j = 0; j < nBytes; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)bytes[j] << " ";
    }
    std::cout << "\n" << std::dec;
    */

    char oldNBytes = nBytes;
    char oldBytes[nBytes];
    
    char oldBuf[DECODING_BUFFER_SIZE];
    char* oldStr = &oldBuf[0];
    int success = !decoder->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE);
    if (!success) {
        return;
    }
    
    //std::cout << "Before trim: " << oldStr << "\n";
    
    memcpy(oldBytes, bytes, nBytes);
    trimUnusedEnd();
    
    /*
    std::cout << "Bytes after trim:\n";
    for (size_t j = 0; j < nBytes; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)bytes[j] << " ";
    }
    std::cout << "\n" << std::dec;
    */

    FieldList* oldFields = fields;
    fields = new FieldList(oldStr);
    deleteOptionalBytes();
    delete fields;
    fields = oldFields;
    
    //success = !decoder->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE);
    //assert(success);
    
    //std::cout << "After optional removal: " << oldStr << "\n";

    char decBuf[DECODING_BUFFER_SIZE];
    char* decStr = &decBuf[0];

    success = !decoder->decode(bytes,
                                    nBytes,
                                    decStr, 
                                    DECODING_BUFFER_SIZE);
    
    if (success) {
        FieldList tList(decStr);
        if (!tList.hasError()) {
            tList.stripHex();
            tList.stripDigits();
            Architecture::replaceRegSets(tList);
            int len = tList.getTotalBytes();
            char* hcString = (char*)malloc(len);
            assert(hcString != NULL);
            tList.fillBuf(hcString, len);

            if (hc->insert(std::make_pair(hcString, 1)).second) {
             
                
                std::cout << decoder->getName() << " queue: " << hcString 
                        << "\n";
                /*
                if (strstr(decStr, "addr32") != NULL) {
                    for (size_t j = 0; j < nBytes; j++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2)
                            << (unsigned int)(unsigned char)bytes[j] << " ";
                    }
                    std::cout << "\n" << std::dec;
                    for (size_t j = 0; j < Architecture::maxInsnLen; j++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2)
                            << (unsigned int)(unsigned char)oldBytes[j] << " ";
                    }
                    std::cout << "\n" << std::dec;
                    
                    exit(-1);
                }
                */
                char* queuedBytes = (char*)malloc(Architecture::maxInsnLen);
                assert(queuedBytes != NULL);
                randomizeBuffer(queuedBytes, Architecture::maxInsnLen);
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
  
    if (isError) {
        return;
    }

    size_t nBits = 8 * nBytes;

    for (size_t i = 0; i < nBits; i++) {
        if (bitTypes[i] != BIT_TYPE_SWITCH) {
            continue;
        }
        flipBufferBit(bytes, i);
        enqueueInsnIfNew(queue, hc);
        flipBufferBit(bytes, i);
    }

    for (size_t i = 0; i < nBits; i++) {

        if (bitTypes[i] != BIT_TYPE_SWITCH) {
            continue;
        }

        flipBufferBit(bytes, i);
        
        for (size_t j = i + 1; j < nBits; j++) {
            if (bitTypes[j] != BIT_TYPE_SWITCH) {
                continue;
            }
            flipBufferBit(bytes, j);
            enqueueInsnIfNew(queue, hc);
            flipBufferBit(bytes, j);
        }

        //printf("%s %d\n", decStr, bitTypes[i]);
        flipBufferBit(bytes, i);
    }

    char startBytes[nBytes];
    memcpy(bytes, startBytes, nBytes);
    for (size_t i = 0; i < fields->size(); i++) {
        for (size_t j = 0; j < nBits; j++) {
            if (bitTypes[j] == (int)i) {
                setBufferBit(bytes, i, 0);
            }
        }
        enqueueInsnIfNew(queue, hc);
        for (size_t j = 0; j < nBits; j++) {
            if (bitTypes[j] == (int)i) {
                setBufferBit(bytes, i, 1);
            }
        }
        enqueueInsnIfNew(queue, hc);
        memcpy(startBytes, bytes, nBytes);
    }
}

MappedInst::MappedInst(char* bytes, unsigned int nBytes, Decoder* dec) {

    char decodeBuf[DECODING_BUFFER_SIZE];
    char* decodedInstruction = &decodeBuf[0];

    decoder = dec;
    int success = !decoder->decode(bytes, 
                                   nBytes, 
                                   decodedInstruction, 
                                   DECODING_BUFFER_SIZE);
   
    fields = new FieldList(decodedInstruction);
    if (success && fields->hasError()) {
        success = false;
    }
    
    isError = !success;
    if (isError) {
        return;
    }

    this->nBytes = nBytes;
    this->bitTypes = (BitType*)malloc(8 * nBytes * sizeof(*bitTypes));
    this->bytes = (char*)malloc(nBytes);
    this->confirmed = (bool*)malloc(8 * nBytes * sizeof(*confirmed));
  
    assert(bitTypes != NULL && bytes != NULL && confirmed != NULL);

    for (size_t i = 0; i < 8 * nBytes; i++) {
        confirmed[i] = false;
    }

    for (unsigned int i = 0; i < nBytes; i++) {
        this->bytes[i] = bytes[i];
    }
  
    trimUnusedEnd();
    deleteOptionalBytes();
    this->map();
}

MappedInst::~MappedInst() {
    delete fields;
    if (isError) {
        return;
    }
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
    fields->print(stdout);
    for (size_t i = 0; i < 8 * nBytes; i++) {
        std::cout << bitTypes[i];
    }
    std::cout << "\n";
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

   decoder->decode(bytes, nBytes, decStr, DECODING_BUFFER_SIZE);
   FieldList startFields = FieldList(decStr);
   std::vector<Bitfield*> bitfields;
   for (size_t j = 0; j < startFields.size(); j++) {
      bitfields.push_back(Bitfield::create(startFields.getField(j)));
   }
   
   // Iterate over each bit, flipping it. Update the bit types with each 
   // test. This is a first pass over the data. This will be a first pass
   // at the instruction. The second pass will try to identify operand
   // switches that don't alter multiple operands at once.
   for (i = 0; consecutiveUnused < CONSECUTIVE_UNUSED_THRESHOLD && i < nBits; i++) {
      if (confirmed[i]) {
          //std::cout << decStr << " " << bTypes[i] << "(C) \n";
          continue;
      }
      flipBufferBit(bytes, i);
      success = !decoder->decode(bytes, nBytes, decStr, DECODING_BUFFER_SIZE);
      FieldList newFields = FieldList(decStr);

      // Default the bit type to unused.
      bTypes[i] = BIT_TYPE_UNUSED;
      if (success && !newFields.hasError()) {
         FieldList newFields = FieldList(decStr);
         bTypes[i] = getBitTypeByChanges(&startFields, decStr);

         if (bTypes[i] >= 0) {

            Bitfield* bf = bitfields[bTypes[i]];
            if (bf != NULL) {
               flipBufferBit(bytes, i); 
               
               int matchLen = bf->matches(bytes, i, nBits);
               if (matchLen > 0) {
                  Bitfield* newBf =
                  Bitfield::create(newFields.getField(bTypes[i]));
                  flipBufferBit(bytes, i);
                  if (newBf != NULL) {
                      int newMatchLen = newBf->matches(bytes, i, nBits);
                      if (newMatchLen == matchLen) {

                          
                          confirmed[i] = true;
                          for (int j = 1; j < matchLen; j++) {
                             confirmed[i + j] = true;
                             bTypes[i + j] = bTypes[i];
                          }
                      }
                  }
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
      }

      //std::cout << decStr << " " << bTypes[i] << "\n";

      consecutiveUnused++;
      if (bTypes[i] != BIT_TYPE_UNUSED) {
         consecutiveUnused = 0;
      }
      flipBufferBit(bytes, i);
   }

   // If we didn't make it to the end of the string, it was unused, so mark all
   // remaining bits unused.
   while (i < nBits) {
      bTypes[i] = BIT_TYPE_UNUSED;
      i++;
   }

    /*
    for (int j = 0; j < nBits; j++) {
        std::cout << bTypes[j];
    }
    std::cout << "\n";
    exit(-1);
    */

   for (auto it = bitfields.begin(); it != bitfields.end(); ++it) {
      if (*it != NULL) {
         delete *it;
      }
   }
}

void MappedInst::mapBitTypes(BitType* bitTypes) {
    size_t i = 0;
    unsigned int nBits = 8 * nBytes;
    char decStr[DECODING_BUFFER_SIZE];
  
    BitType tmpBitTypeBuf[nBits];
    BitType newBitTypeBuf[nBits];
    BitType* tmpBitTypes = &tmpBitTypeBuf[0];
    BitType* newBitTypes = &newBitTypeBuf[0];
   
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

    /*
    for (int i = 0; i < 8 * nBytes; i++) {
        std::cout << bitTypes[i];
    }
    std::cout << "\n";
    exit(-1);
    */
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

