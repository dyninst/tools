
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

//#define INSN_QUEUE_COUNTING
#define INSN_QUEUE_COUNTING_FILENAME "queue_counter.txt"

unsigned long long MappedInst::totalQueueingTime = 0;
unsigned long long MappedInst::totalLabellingTime = 0;
unsigned long long MappedInst::t1 = 0;
unsigned long long MappedInst::t2 = 0;

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
                                   DECODING_BUFFER_SIZE, false);
   
    fields = new FieldList(decodedInstruction);
    if (success && fields->hasError()) {
        success = false;
    }
  
    this->nBytes = toCopy->nBytes;
    this->bytes = (char*)malloc(this->nBytes);
    bcopy(toCopy->bytes, this->bytes, this->nBytes);
    this->map = new SimpleInsnMap(toCopy->map);
}

static bool fieldsMatch(const char* field1, const char* field2) {
    if (!strcmp(field1, field2)) {
        return true;
    }
    if (*field1 == '0' && *(field1 + 1) == 'x' && *field2 == '0' && *(field2 + 1) == 'x') {
        if (atof(field1) == atof(field2) - 1) {
            return true;
        }
    }
    return false;
}

bool MappedInst::isByteOptional(Decoder* decoder, char* bytes, size_t nBytes, size_t whichByte, FieldList* oldFields) {

    // Allocated a buffer that we can fill with the decoded version of this instruction.
    char newBuf[DECODING_BUFFER_SIZE];
    bzero(newBuf, DECODING_BUFFER_SIZE);
    char* newStr = &newBuf[0];

    // Allocate a buffer for the bytes of this instruction with a single byte removed.
    char newBytes[nBytes - 1];
    //bzero(newBytes, nBytes - 1);
    size_t j = 0;

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
            DECODING_BUFFER_SIZE, false);

    // If the instruction fails to decode, the removed byte is not optional.
    if (!success) {
        return false;
    }

    // Construct a field list from the new instruction so we can compare field-by-field with the 
    // old instruction.
    FieldList new_fields = FieldList(newStr);

    if (new_fields.size() > oldFields->size()) {
        return false;
    }
    
    // If the new instruction has a field that indicates a decoding error, the removed byte is
    // not optional.
    if (new_fields.hasError()) {
        return false;
    }
    
    // The byte was optional if and only if the new decoding constains a subset of the fields in
    // the old decoding. To verify this, we check if each field in the new decoding exists in the
    // old one.
    j = 0;
    const char* oldField = oldFields->getField(j);
    for (size_t i = 0; i < new_fields.size(); i++) {
        const char* newField = new_fields.getField(i);
        while (j < oldFields->size() - 1 && !fieldsMatch(newField, oldField)) {
            ++j;
            if (oldFields->size() - j < new_fields.size() - i) {
                return false;
            }
            oldField = oldFields->getField(j);
        }
        if (j == oldFields->size() && !fieldsMatch(newField, oldField)) {
            return false;
        }
    }
    
    return true;
}

void MappedInst::enqueueInsnIfNew(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc, std::vector<Decoder> decoders) {
    
    struct timespec startTime;
    struct timespec endTime;
    static bool printQueue = (Options::get("-pig") != NULL);
    char oldBuf[DECODING_BUFFER_SIZE];
    char* oldStr = &oldBuf[0];
    int success = !decoder->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE, false);
    if (!success) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &startTime);
    bool seen = true;

    char decBuf[DECODING_BUFFER_SIZE];
    char* decStr = &decBuf[0];

    success = !decoder->decode(bytes,
                                    nBytes,
                                    decStr, 
                                    DECODING_BUFFER_SIZE, true);
    
    if (!success) {
        return;
    }
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
            seen = false;
        } else {
            free(hcString);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    t1 += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                      (endTime.tv_nsec - startTime.tv_nsec);

    if (seen) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &startTime);
    FieldList oldFields = FieldList(oldStr);
    int nOptional = 0;
    for (size_t i = 0; i < nBytesUsed && nOptional < 3; ++i) {
        if (isByteOptional(decoder, bytes, nBytes, i, &oldFields)) {
            ++nOptional;
        }
    }
    if (nOptional > 2) {
        return;
    }
    clock_gettime(CLOCK_MONOTONIC, &endTime);

    t2 += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                      (endTime.tv_nsec - startTime.tv_nsec);
    
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
        std::cout << std::dec << "): ";
        tList.printInsn(stdout);
        std::cout << "\n";
    }
    
    clock_gettime(CLOCK_MONOTONIC, &startTime);
    for (size_t i = 0; i < decoders.size(); ++i) {
        Decoder* otherDecoder = &(decoders[i]);
        if (otherDecoder == decoder) {
            continue;
        }

        success = !otherDecoder->decode(bytes,
                                        nBytes,
                                        decStr, 
                                        DECODING_BUFFER_SIZE, true);
        
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

                if (!hc->insert(std::make_pair(hcString, 1)).second) {
                    free(hcString);
                }
            }
        }
    }
    char* queuedBytes = (char*)malloc(Architecture::maxInsnLen);
    assert(queuedBytes != NULL);
    randomizeBuffer(queuedBytes, Architecture::maxInsnLen);
    bcopy(bytes, queuedBytes, nBytes);
    queue->push(queuedBytes);
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    t1 += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                      (endTime.tv_nsec - startTime.tv_nsec);

}

void MappedInst::queueNewInsns(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc, std::vector<Decoder> decoders) {
    
    struct timespec startTime;
    struct timespec endTime;
    clock_gettime(CLOCK_MONOTONIC, &startTime);
  
    if (isError) {
        return;
    }

    #ifdef INSN_QUEUE_COUNTING
        static FILE* INSN_QUEUE_COUNTING_FILE = fopen(INSN_QUEUE_COUNTING_FILENAME, "w+");
        assert(INSN_QUEUE_COUNTING_FILE != NULL);
        int nTriedToQueue = 0;
        int nQueuedDoubleFlip = 0;
        int nQueuedSingleFlip = 0;
        int nQueuedRandom = 0;
        int nQueuedSpecial = 0;
        int lastQueueSize = queue->size();
    #endif

    size_t nBits = 8 * nBytesUsed;
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
            #ifdef INSN_QUEUE_COUNTING
                ++nTriedToQueue;
            #endif
            enqueueInsnIfNew(queue, hc, decoders);
            flipBufferBit(bytes, j);
        }

        flipBufferBit(bytes, i);
    }

    #ifdef INSN_QUEUE_COUNTING
        nQueuedDoubleFlip = queue->size() - lastQueueSize;
        lastQueueSize = queue->size();
    #endif

    for (i = 0; i < nBits; i++) {
        if (map->getBitType(i) != BIT_TYPE_SWITCH) {
            continue;
        }
        flipBufferBit(bytes, i);
        #ifdef INSN_QUEUE_COUNTING
            ++nTriedToQueue;
        #endif
        enqueueInsnIfNew(queue, hc, decoders);
        flipBufferBit(bytes, i);
    }

    #ifdef INSN_QUEUE_COUNTING
        nQueuedSingleFlip = queue->size() - lastQueueSize;
        lastQueueSize = queue->size();
    #endif

    char startBytes[nBytes];
    memcpy(&startBytes[0], bytes, nBytes);
    
    for (i = 0; i < fields->size(); i++) {
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, j, rand() & 0x01);
            }
        }
        enqueueInsnIfNew(queue, hc, decoders);
        #ifdef INSN_QUEUE_COUNTING
            ++nTriedToQueue;
            nQueuedRandom += queue->size() - lastQueueSize;
            lastQueueSize = queue->size();
        #endif
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, j, 0);
            }
        }
        enqueueInsnIfNew(queue, hc, decoders);

        #ifdef INSN_QUEUE_COUNTING
            ++nTriedToQueue;
            nQueuedSpecial += queue->size() - lastQueueSize;
            lastQueueSize = queue->size();
        #endif
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, j, 1);
            }
        }
        enqueueInsnIfNew(queue, hc, decoders);
        #ifdef INSN_QUEUE_COUNTING
            ++nTriedToQueue;
            nQueuedSpecial += queue->size() - lastQueueSize;
            lastQueueSize = queue->size();
        #endif
        memcpy(bytes, &startBytes[0], nBytes);
    }
    #ifdef INSN_QUEUE_COUNTING
    fprintf(INSN_QUEUE_COUNTING_FILE, "Tried: %d\tDouble: %d\tSingle: %d\tRandom: %d\tSpecial: %d\n",
        nTriedToQueue, nQueuedDoubleFlip, nQueuedSingleFlip, nQueuedRandom, nQueuedSpecial);
    fflush(INSN_QUEUE_COUNTING_FILE);
    #endif
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    totalQueueingTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                      (endTime.tv_nsec - startTime.tv_nsec);
}

MappedInst::MappedInst(char* bytes, unsigned int nBytes, Decoder* dec) {

    struct timespec startTime;
    struct timespec endTime;
    clock_gettime(CLOCK_MONOTONIC, &startTime);
    char decodeBuf[DECODING_BUFFER_SIZE];
    char* decodedInstruction = &decodeBuf[0];

    decoder = dec;

    int success = !decoder->decode(bytes, 
                                   nBytes, 
                                   decodedInstruction, 
                                   DECODING_BUFFER_SIZE, false);
   
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
    this->mapBitTypes();
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    totalLabellingTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                      (endTime.tv_nsec - startTime.tv_nsec);
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
    unsigned int nBitsUsed = 8 * nBytesUsed;
    
    map = new SimpleInsnMap(bytes, nBytes, nBytesUsed, decoder);
    SimpleInsnMap prelimMap = SimpleInsnMap(map);
    #ifdef COUNTING_OPCODE_COMBOS

    MappedInst* storedMap = new MappedInst(this);
    bool operandUse[nBits];

    for (size_t i = 0; i < nBits; ++i) {
        operandUse[i] = false;
    }

    #endif

    for (i = 0; i < nBitsUsed; i++) {
        if (map->getBitType(i) == BIT_TYPE_SWITCH        ||
            map->getBitType(i) == BIT_TYPE_CAUSED_ERROR  ||
            map->isBitConfirmedImm(i)) {

            continue;
        }

        flipBufferBit(bytes, i);
        SimpleInsnMap newMap = SimpleInsnMap(bytes, nBytes, nBytesUsed, decoder);
        if (!prelimMap.isMapEquivalent(newMap)) {
            
            if (map->getBitType(i) != 0 && nBytesUsed <= 3) {
                /*
                std::cout << "Changing bit " << i << " from field " << (int)prelimMap.getBitType(i) << "\n";
                for (size_t j = 0; j < nBytes; j++) {
                    std::cout << std::hex << std::setfill('0') << std::setw(2)
                        << (unsigned int)(unsigned char)bytes[j] << " " << std::dec;
                }
                fields->printInsn(stdout);
                std::cout << "\nOld map: " << prelimMap.toString() << "\n";
                std::cout << "New map: " << newMap.toString() << "\n";
                */
                //exit(-1);
            }
            
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
    //std::cout << "Final map: " << map->toString() << "\n";
    //exit(-1);

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
    char byteBuf[nBytes];
    
    // The number of bytes required to produce an error isn't a defined quantity, so we won't trim
    // any bytes from an error.
    int success = !dec->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE, false);
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
        byteBuf[i - 1] = bytes[i - 1];
        int newSuc = !dec->decode(byteBuf, i, newStr, DECODING_BUFFER_SIZE, false);
        if (newSuc && !strcmp(newStr, oldStr)) {
            return i;
        }
    }

    return nBytes;
}
