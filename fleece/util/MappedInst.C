
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

#define NUM_OPTIONAL_BYTES_ALLOWED 2

std::map<MappedInst*, MappedInst*, MappedInst::insn_cmp> MappedInst::uniqueMaps;

void setInstructionBitVector(char* bytes, int* switchBits, int nSwitchBits, int i);
void printBitTypes(BitType* bitTypes, unsigned int nBits);

MappedInst::MappedInst(MappedInst* toCopy) {
    
    this->isError = toCopy->isError;
    if (this->isError) {
        return;
    }
    
    char decodeBuf[DECODING_BUFFER_SIZE];
    char* decodedInstruction = &decodeBuf[0];

    this->decoder = toCopy->decoder;

    int success = !decoder->decode(toCopy->bytes, 
                                   toCopy->nBytes, 
                                   decodedInstruction, 
                                   DECODING_BUFFER_SIZE);
   
    fields = new FieldList(decodedInstruction);
    if (success && fields->hasError()) {
        success = false;
    }
  
    this->nBytes = toCopy->nBytes;
    this->bytes = (char*)malloc(this->nBytes);
    bcopy(toCopy->bytes, this->bytes, this->nBytes);
    this->map = new SimpleInsnMap(toCopy->map);

}

bool MappedInst::isByteOptional(size_t whichByte) {

    // Allocated a buffer that we can fill with the decoded version of this instruction.
    char newBuf[DECODING_BUFFER_SIZE];
    bzero(newBuf, DECODING_BUFFER_SIZE);
    char* newStr = &newBuf[0];

    // Allocate a buffer for the bytes of this instruction with a single byte removed.
    char newBytes[nBytes - 1];
    bzero(newBytes, nBytes - 1);
    int j = 0;

    // Copy over all bytes excluding the byte that we want to test. If the byte can be removed and
    // the instruction only changes in certain ways (or not at all), the byte is optional.
    //
    // Example:
    //
    // Original Bytes:   FE 0D A1 48 E2
    //                      ^
    //                      |
    //            removed if whichByte = 2
    //
    // New Bytes:        FE A1 48 E2

    for (size_t i = 0; i < nBytes; i++) {
        if (i != whichByte) {
            newBytes[j] = bytes[i];
            j++;
        }
    }

    // Decode the instruction again with the new bytes created above.
    bool success = !decoder->decode(newBytes, nBytes - 1, newStr, 
            DECODING_BUFFER_SIZE);

    // If the instruction fails to decode, the removed byte is not optional.
    if (!success) {
        return false;
    }

    // Construct a field list from the new instruction so we can compare field-by-field with the 
    // old instruction.
    FieldList new_fields = FieldList(newStr);
    
    // If the new instruction has a field that indicates a decoding error, the removed byte is
    // not optional.
    if (new_fields.hasError()) {
        return false;
    }
    
    // The byte was optional if and only if the new decoding constains a subset of the fields in
    // the old decoding. To verify this, we check if each field in the new decoding exists in the
    // old one.
    for (size_t i = 0; i < new_fields.size(); i++) {
        const char* curField = new_fields.getField(i);
        bool foundField = true;
        if (!fields->hasField(curField)) {
            foundField = false;

            // Since we decreased the length of the instruction by one, jump
            // destinations may be one byte less, so search for that field.
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
    
    return true;
}

void MappedInst::deleteDownToNOptionalBytes(size_t n) {

    // Keep track of which bytes were optional an how many optional bytes were found.
    bool optional[nBytes];
    size_t nOptional = 0;

    // Determine which bytes are optional.
    for (size_t i = 0; i < nBytesUsed; i++) {
        optional[i] = isByteOptional(i);
        nOptional++;
    }

    // Skip the first nOptional - n bytes that were optional. This allows at most n optional bytes
    // to remain.
    size_t nSkipped = 0;
    size_t nToSkip = nOptional - n;
    size_t nextByteSlot = 0;

    for (size_t i = 0; i < nBytesUsed; ++i) {
        if (!optional[i] || nSkipped >= nToSkip) {
            bytes[nextByteSlot] = bytes[i];
            ++nextByteSlot;
        } else {
            ++nSkipped;
        }
    }

    for (size_t i = nBytesUsed; i < nBytes; ++i) {
        bytes[nextByteSlot] = bytes[i];
        ++nextByteSlot;
    }

    // We should maintain instruction length, so fill it with random bytes.
    for (size_t i = 0; i < nSkipped; ++i) {
        bytes[nextByteSlot] = (char)(rand() & 0xFF);
        ++nextByteSlot;
    }
    
    // Now that we have removed the optional bytes, we need to update this mapped instruction's
    // fields to reflect this change.
    char newBuf[DECODING_BUFFER_SIZE];
    char* newStr = &newBuf[0];
    decoder->decode(bytes, nBytes, newStr, DECODING_BUFFER_SIZE);
    delete fields;
    fields = new FieldList(newStr);
   
    /*
    std::cout << "Final bytes:\n\t";
    for (size_t j = 0; j < nBytes; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)bytes[j] << " ";
    }
    std::cout << "\n";
    */
}

/*
void MappedInst::trimUnusedEnd() {
    
    // This method will remove all of the bytes at the end of an instruction that can be removed
    // without affecting the outcome of decoding.
    char oldBuf[DECODING_BUFFER_SIZE];
    char* oldStr = &oldBuf[0];
    
    // The number of bytes required to produce an error isn't a defined quantity, so we won't trim
    // any bytes from an error.
    int success = !decoder->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE);
    if (!success) {
        return;
    }

    // This buffer will hold the new decoding after trailing bytes are removed.
    char newBuf[DECODING_BUFFER_SIZE];
    char* newStr = &newBuf[0];

    // Start with an instruction of length one and increase the instruction length up to the
    // original length. Return the shortest instruction whose output is identical to the
    // original instruction.
    for (size_t i = 1; i < nBytes; i++) {
        int newSuc = !decoder->decode(bytes, i, newStr, DECODING_BUFFER_SIZE);
        if (newSuc && !strcmp(newStr, oldStr)) {
            nBytes = i;
            //std::cout << "|-- UNUSED TRIMMED (len = " << nBytes << ") --|\n";
            return;
        }
    }
}
*/

void MappedInst::enqueueInsnIfNew(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc) {
    static bool printQueue = (Options::get("-pig") != NULL);

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
    //trimUnusedEnd();
    
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
    deleteDownToNOptionalBytes(NUM_OPTIONAL_BYTES_ALLOWED);
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
             
                if (printQueue) {  
                    std::cout << decoder->getName();
                    size_t decNameLen = strlen(decoder->getName());
                    for (size_t j = 0; j < 9 - decNameLen; ++j) {
                        std::cout << " ";
                    }
                    std::cout << "queue: ";
                    for (size_t j = 0; j < nBytesUsed; ++j) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2)
                            << (unsigned int)(unsigned char)bytes[j] << " ";
                    }
                    std::cout << "(";
                    for (size_t j = nBytesUsed; j < nBytes; ++j) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2)
                            << (unsigned int)(unsigned char)bytes[j] << " ";
                    }
                    std::cout << std::dec << "): " << hcString << "\n";
                }
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
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < nBits; i++) {

        if (map->getBitType(i) != BIT_TYPE_SWITCH) {
            continue;
        }

        flipBufferBit(bytes, i);
        
        for (j = i + 1; j < nBits; j++) {
            if (map->getBitType(j) != BIT_TYPE_SWITCH) {
                continue;
            }
            flipBufferBit(bytes, j);
            enqueueInsnIfNew(queue, hc);
            flipBufferBit(bytes, j);
        }

        //printf("%s %d\n", decStr, bitTypes[i]);
        flipBufferBit(bytes, i);
    }

    for (i = 0; i < nBits; i++) {
        if (map->getBitType(i) != BIT_TYPE_SWITCH) {
            continue;
        }
        flipBufferBit(bytes, i);
        enqueueInsnIfNew(queue, hc);
        flipBufferBit(bytes, i);
    }

    char startBytes[nBytes];
    for (i = 0; i < nBytes; i++) {
        startBytes[i] = 0;
    }

    memcpy(bytes, startBytes, nBytes);
    for (i = 0; i < fields->size(); i++) {
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, i, rand() & 0x01);
            }
        }
        enqueueInsnIfNew(queue, hc);
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, i, 0);
            }
        }
        enqueueInsnIfNew(queue, hc);
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
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
    this->bytes = (char*)malloc(nBytes);
    assert(bytes != NULL);
    bcopy(bytes, this->bytes, nBytes);

    this->nBytesUsed = findNumBytesUsed(bytes, nBytes, dec);
    deleteDownToNOptionalBytes(NUM_OPTIONAL_BYTES_ALLOWED);
    this->mapBitTypes();
}

MappedInst::~MappedInst() {
    delete fields;
    if (isError) {
        return;
    }
    free(bytes);
    delete map;
}

void MappedInst::mapBitTypes() {
    size_t i = 0;
    unsigned int nBits = 8 * nBytes;
    
    map = new SimpleInsnMap(bytes, nBytes, nBytesUsed, decoder);

    #ifdef COUNTING_OPCODE_COMBOS

    MappedInst* storedMap = new MappedInst(this);
    bool operandUse[nBits];

    for (size_t i = 0; i < nBits; ++i) {
        operandUse[i] = false;
    }

    #endif

    for (i = 0; i < nBits; i++) {
        if (map->getBitType(i) == BIT_TYPE_UNUSED        ||
            map->getBitType(i) == BIT_TYPE_SWITCH        ||
            map->getBitType(i) == BIT_TYPE_CAUSED_ERROR  ||
            map->isBitConfirmedImm(i)) {

            continue;
        }

        flipBufferBit(bytes, i);
        SimpleInsnMap newMap = SimpleInsnMap(bytes, nBytes, nBytesUsed, decoder);
        if (!map->isMapEquivalent(newMap)) {
            map->overrideBitType(i, BIT_TYPE_SWITCH);
        }
        
        #ifdef COUNTING_OPCODE_COMBOS
        if (!map->isOpcodeBit(i)) {
            for (size_t j = 0; j < nBits; ++j) {
                if (newMap.getBitType(j) >= 0) {
                    operandUse[j] = true;
                }
            }
        }
        #endif
        
        flipBufferBit(bytes, i);
    }

    #ifdef COUNTING_OPCODE_COMBOS

    //std::cout << "Operand use map: ";

    for (size_t i = 0; i < nBits; ++i) {

        /*
        if (operandUse[i]) {
            std::cout << "O";
        } else {
            std::cout << "*";
        }
        */

        if (storedMap->map->isOpcodeBit(i) == (char)107) {
            std::cerr << "Found unset upcode bit! (i = " << i << ")" << std::endl;
            exit(-1);
        }
        if (storedMap->map->isOpcodeBit(i)) {
            storedMap->map->overrideBitType(i, BIT_TYPE_SWITCH);
        } else if (storedMap->map->getBitType(i) == BIT_TYPE_CAUSED_ERROR && !operandUse[i]) {
            storedMap->map->overrideBitType(i, BIT_TYPE_SWITCH);
        } else {
            storedMap->map->overrideBitType(i, 0);
        }
    }

    //std::cout << std::endl;
    
    bool mapWasNew = false;
    if (!storedMap->isError && !storedMap->fields->hasError() && MappedInst::uniqueMaps.count(storedMap) == 0) {
        MappedInst::uniqueMaps[storedMap] = storedMap;
        std::cout << "Num maps = " << MappedInst::uniqueMaps.size() << "\n";
        mapWasNew = true;
    
        for (size_t j = 0; j < 8 * storedMap->getNumBytes(); j++) {
            if (storedMap->getBitType(j) == BIT_TYPE_SWITCH) {
                std::cout << "*";
            } else if (storedMap->getBitType(j) == BIT_TYPE_UNUSED) {
                std::cout << "x";
            } else if (storedMap->getBitType(j) == BIT_TYPE_CAUSED_ERROR) {
                std::cout << "E";
            } else {
                std::cout << storedMap->getBitType(j);
            }
        }
        std::cout << "  ";
        char* bytes = storedMap->getRawBytes();
        for (size_t j = 0; j < storedMap->getNumBytes(); j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                << (unsigned int)(unsigned char)bytes[j] << " ";
        }
        std::cout << std::dec;
        std::cout << "  ";
        storedMap->getFields()->printInsn(stdout);
        std::cout << "\n";
    }
  
    if (!mapWasNew) {
        delete storedMap;
    }

    #endif
}

void setInstructionBitVector(char* inst, int* bitPositions, unsigned int nBit, int value) {
   for (unsigned int i = nBit - 1; i >= 0; i--) {
      setBufferBit(inst, bitPositions[i], value & 0x01);
      value = value >> 1;
   }
}
    
BitType MappedInst::getBitType(size_t whichBit) const { 
    return map->getBitType(whichBit); 
}

size_t MappedInst::findNumBytesUsed(char* bytes, size_t nBytes, Decoder* dec) {
    
    // This method will remove all of the bytes at the end of an instruction that can be removed
    // without affecting the outcome of decoding.
    char oldBuf[DECODING_BUFFER_SIZE];
    char* oldStr = &oldBuf[0];
    
    // The number of bytes required to produce an error isn't a defined quantity, so we won't trim
    // any bytes from an error.
    int success = !dec->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE);
    if (!success) {
        return nBytes;
    }

    // This buffer will hold the new decoding after trailing bytes are removed.
    char newBuf[DECODING_BUFFER_SIZE];
    char* newStr = &newBuf[0];

    // Start with an instruction of length one and increase the instruction length up to the
    // original length. Return the shortest instruction whose output is identical to the
    // original instruction.
    for (size_t i = 1; i < nBytes; i++) {
        int newSuc = !decoder->decode(bytes, i, newStr, DECODING_BUFFER_SIZE);
        if (newSuc && !strcmp(newStr, oldStr)) {
            return i;
        }
    }

    return nBytes;
}
