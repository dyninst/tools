
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

#include "MappedInsn.h"

#define NUM_OPTIONAL_BYTES_ALLOWED 2

/*
 * Returns true if two fields are equivalent, given one byte was removed from
 * the original instruction. This is a bit tricky, because branch addresses
 * will be reduced by one, since they are relative to the end of the
 * instruction.
 *
 * Fields are equivalent iff:
 *  - They are exact string matches.
 *    OR
 *  - They are immediates.
 *  - The seconds field is equal to the first field minus 1.
 *
 * Note: Since the same decoder is being used in both cases, formatting will
 * be identical for identical fields.
 */
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

bool MappedInsn::isByteOptional(Decoder* decoder, char* bytes, size_t nBytes, size_t whichByte, FieldList* oldFields) {

    // Allocated a buffer that we can fill with the decoded version of this instruction.
    char newBuf[DECODING_BUFFER_SIZE];
    bzero(newBuf, DECODING_BUFFER_SIZE);
    char* newStr = &newBuf[0];

    // Allocate a buffer for the bytes of this instruction with a single byte removed.
    char newBytes[nBytes - 1];
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

    // If the new instruction has more fields, the byte was not optional.
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

void MappedInsn::enqueueInsnIfNew(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc, std::vector<Decoder*> decoders) {
    
    static bool printQueue = (Options::get("-pig") != NULL);
    bool seen = true;
    char decBuf[DECODING_BUFFER_SIZE];
    char* decStr = &decBuf[0];

    // Test if the instruction has been seen before.
    int success = !decoder->decode(bytes, nBytes, decStr, DECODING_BUFFER_SIZE,
        true);
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

    if (seen) {
        return;
    }
    
    // Test if the instruction has too many optional bytes.
    char oldBuf[DECODING_BUFFER_SIZE];
    char* oldStr = &oldBuf[0];
    success = !decoder->decode(bytes, nBytes, oldStr, DECODING_BUFFER_SIZE,
        false);
    
    if (!success) {
        return;
    }


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
    
    // The instruction's format has not been seen before, and it has an
    // acceptable number of optional bytes.
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
    
    // Enter the format string for this instruction into the list of seen
    // formats for each of the decoders.
    for (size_t i = 0; i < decoders.size(); ++i) {
        Decoder* otherDecoder = decoders[i];
        if (otherDecoder == decoder) {
            continue;
        }

        success = !otherDecoder->decode(bytes, nBytes, decStr,
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

    // Enqueue this instructions bytes.
    char* queuedBytes = (char*)malloc(Architecture::getMaxInsnLen());
    assert(queuedBytes != NULL);
    randomizeBuffer(queuedBytes, Architecture::getMaxInsnLen());
    bcopy(bytes, queuedBytes, nBytes);
    queue->push(queuedBytes);
}

void MappedInsn::queueNewInsns(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc, std::vector<Decoder*> decoders) {
    
    /* We don't mutate error instructions */
    if (isError) {
        return;
    }

    size_t nBits = 8 * nBytesUsed;
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < nBits; i++) {

        if (map->getBitType(i) != BIT_TYPE_STRUCTURAL) {
            continue;
        }

        flipBufferBit(bytes, i);
        
        for (j = i + 1; j < nBits; j++) {
            if (map->getBitType(j) != BIT_TYPE_STRUCTURAL) {
                continue;
            }
            flipBufferBit(bytes, j);
            enqueueInsnIfNew(queue, hc, decoders);
            flipBufferBit(bytes, j);
        }

        flipBufferBit(bytes, i);
    }

    for (i = 0; i < nBits; i++) {
        if (map->getBitType(i) != BIT_TYPE_STRUCTURAL) {
            continue;
        }
        flipBufferBit(bytes, i);
        enqueueInsnIfNew(queue, hc, decoders);
        flipBufferBit(bytes, i);
    }

    char startBytes[nBytes];
    memcpy(&startBytes[0], bytes, nBytes);
    
    for (i = 0; i < fields->size(); i++) {
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, j, rand() & 0x01);
            }
        }
        enqueueInsnIfNew(queue, hc, decoders);
        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, j, 0);
            }
        }
        enqueueInsnIfNew(queue, hc, decoders);

        for (j = 0; j < nBits; ++j) {
            if (map->getBitType(j) == (int)i) {
                setBufferBit(bytes, j, 1);
            }
        }
        enqueueInsnIfNew(queue, hc, decoders);
        memcpy(bytes, &startBytes[0], nBytes);
    }
}

MappedInsn::MappedInsn(char* bytes, unsigned int nBytes, Decoder* dec) {
    char decodeBuf[DECODING_BUFFER_SIZE];
    char* decodedInstruction = &decodeBuf[0];

    decoder = dec;

    int success = !decoder->decode(bytes, nBytes, decodedInstruction,
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
}

MappedInsn::~MappedInsn() {
    delete fields;
    if (isError) {
        return;
    }
    free(bytes);
    delete map;
}

void MappedInsn::mapBitTypes() {
    size_t i = 0;
    unsigned int nBitsUsed = 8 * nBytesUsed;
   
    // Create a SimpleInsnMap for the input bytes (this is the preliminary
    // labelling step).
    map = new SimpleInsnMap(bytes, nBytes, nBytesUsed, decoder);
    SimpleInsnMap prelimMap = SimpleInsnMap(map);

    // For each bit with a preliminary label that wasn't structural, reserved
    // or a confirmed immediate, flip the bit and recompute the preliminary
    // labels. If they differ, override the bit type to be structural.
    for (i = 0; i < nBitsUsed; i++) {
        if (map->getBitType(i) == BIT_TYPE_STRUCTURAL ||
            map->getBitType(i) == BIT_TYPE_RESERVED   ||
            map->isBitConfirmedImm(i)) {

            continue;
        }

        flipBufferBit(bytes, i);
        SimpleInsnMap newMap = SimpleInsnMap(bytes, nBytes, nBytesUsed, decoder);
        if (!prelimMap.isMapEquivalent(newMap)) {
            map->overrideBitType(i, BIT_TYPE_STRUCTURAL);
        }
        flipBufferBit(bytes, i);
    }
}

BitType MappedInsn::getBitType(size_t whichBit) const { 
    return map->getBitType(whichBit); 
}

size_t MappedInsn::findNumBytesUsed(char* bytes, size_t nBytes, Decoder* dec) {
    
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
