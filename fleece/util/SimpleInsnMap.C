
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

#include "SimpleInsnMap.h"

//#define DEBUG_SIMPLE_MAP
    
int getBitTypeByChanges(FieldList& startFields, FieldList& newFields);

SimpleInsnMap::SimpleInsnMap(SimpleInsnMap* toCopy) {
    nBits = toCopy->nBits;
    nBitsUsed = toCopy->nBitsUsed;
    bitTypes = new BitType[nBits * sizeof(*bitTypes)];
    confirmedImm = new bool[nBits * sizeof(*confirmedImm)];

    bcopy(toCopy->bitTypes, bitTypes, nBits * sizeof(*bitTypes));
    bcopy(toCopy->confirmedImm, confirmedImm, nBits * sizeof(*confirmedImm));
}

SimpleInsnMap::SimpleInsnMap(const char* bytes, size_t nBytes, size_t nBytesUsed, Decoder* dec) {
    
    nBits = 8 * nBytes;
    nBitsUsed = 8 * nBytesUsed;
    bitTypes = new BitType[nBits * sizeof(*bitTypes)];
    confirmedImm = new bool[nBits * sizeof(*confirmedImm)];
    for (size_t i = 0; i < nBits; i++) {
        confirmedImm[i] = false;
    }
    
    char tmpBytes[nBytes];
    bcopy(bytes, tmpBytes, nBytes);
    mapBitTypes(tmpBytes, dec);
}

SimpleInsnMap::~SimpleInsnMap() {
    delete [] bitTypes;
    delete [] confirmedImm;
}

void SimpleInsnMap::mapBitTypes(char* bytes, Decoder* dec) {
    bool success = false;
    char decStr[DECODING_BUFFER_SIZE];

    bool isError = (bool)dec->decode(bytes, nBits / 8, decStr, DECODING_BUFFER_SIZE, false);
    
    FieldList startFields = FieldList(decStr);
    isError |= startFields.hasError();

    #ifdef DEBUG_SIMPLE_MAP
    std::cout << "Starting insn = " << decStr << "\n";
    for (size_t j = 0; j < nBits / 8; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)bytes[j] << " ";
    }
    std::cout << std::dec << std::endl;
    #endif

    std::vector<Bitfield*> bitfields = std::vector<Bitfield*>();
    for (size_t j = 0; j < startFields.size(); j++) {
        bitfields.push_back(Bitfield::create(startFields.getField(j)));
    }
   
    // Iterate over each bit, flipping it. Update the bit types with each 
    // test. This is a first pass over the data. This will be a first pass
    // at the instruction. The second pass will try to identify operand
    // switches that don't alter multiple operands at once.
    size_t i = 0;
    for (i = 0; i < nBitsUsed; i++) {
        #ifdef DEBUG_SIMPLE_MAP
        std::cout << std::setfill('0') << std::setw(2) << i << ": ";
        #endif

        if (confirmedImm[i]) {
            #ifdef DEBUG_SIMPLE_MAP
            std::cout << decStr << " (field " << bitTypes[i] << " C) \n";
            #endif
            continue;
        }
        flipBufferBit(bytes, i);
        success = !dec->decode(bytes, nBits / 8, decStr, DECODING_BUFFER_SIZE, false);
        FieldList newFields = FieldList(decStr);
      
        #ifdef DEBUG_SIMPLE_MAP
        for (size_t j = 0; j < nBitsUsed / 8; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                << (unsigned int)(unsigned char)bytes[j] << " ";
        }
        std::cout << "(";
        for (size_t j = nBitsUsed / 8; j < nBits / 8; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                << (unsigned int)(unsigned char)bytes[j] << " ";
        }
        std::cout << std::dec << "): " << decStr << std::endl;
        #endif

        // Default the bit type to unused.
        bitTypes[i] = BIT_TYPE_UNUSED;
        if (success && !newFields.hasError()) {
            bitTypes[i] = getBitTypeByChanges(startFields, newFields);

            // If the bit was assigned to a single field, it may be a part of
            // an immediate. Check for that by comparing the field value to
            // the bits that represent the field (immediates will be equal).
            if (bitTypes[i] >= 0) {

                // Get the bit field object associated with this field. If it
                // is NULL, the field is not an immediate.
                Bitfield* bf = bitfields[bitTypes[i]];
                if (bf != NULL) {

                    // Revert the bit that we just flipped, so the value in the
                    // original fields should match the bit.
                    flipBufferBit(bytes, i); 
               
                    int matchLen = bf->matches(bytes, i, nBitsUsed);
                    if (matchLen > 0) {

                        // We matches bits of the immediate to the instruction.
                        // Now, confirm by flipping the first bit and checking
                        // if the immediate changes as expected.
                        Bitfield* newBf = Bitfield::create(newFields.getField(bitTypes[i]));
                        flipBufferBit(bytes, i);
                        if (newBf != NULL) {
                            int newMatchLen = newBf->matches(bytes, i, nBitsUsed);
                            if (newMatchLen == matchLen) {
                                
                                #ifdef DEBUG_SIMPLE_MAP
                                std::cout << "Matched " << matchLen << " bits at bit " << i << "\n";
                                std::cout << "\t" << decStr << " (field " << bitTypes[i] << ")\n";
                                #endif
                                
                                // The immediate changed as expected. Each bit
                                // of the immediate should now be labelled as
                                // confirmed, so we don't retest them later.
                                confirmedImm[i] = true;
                                for (int j = 1; j < matchLen; j++) {
                                    confirmedImm[i + j] = true;
                                    bitTypes[i + j] = bitTypes[i];
                                }
                            }
                        }
                        delete newBf;
                    } else {
                        flipBufferBit(bytes, i);
                    }
                }
            }
        } else {
            bitTypes[i] = BIT_TYPE_RESERVED;
            if (isError) {
                bitTypes[i] = BIT_TYPE_UNUSED;
            }
        }
        flipBufferBit(bytes, i);
    }

    // If we didn't make it to the end of the string, it was unused, so mark all
    // remaining bits unused.
    while (i < nBits) {
        bitTypes[i] = BIT_TYPE_UNUSED;
        i++;
    }

    for (auto it = bitfields.begin(); it != bitfields.end(); ++it) {
        if (*it != NULL) {
            delete *it;
        }
    }
}

int getBitTypeByChanges(FieldList& startFields, FieldList& newFields) {
    BitType result = BIT_TYPE_UNUSED;
   
    if (newFields.size() != startFields.size()) {
        return BIT_TYPE_STRUCTURAL;
    } else {
            
        // We have the same operator, so we can continue looking at
        // operands.
        for (unsigned int i = 0; i < newFields.size(); i++) {
            if (strcmp(newFields.getField(i), startFields.getField(i))) {

                // If the bit hasn't caused a change so far, it may only be a part
                // of this operand. If it has changed one already, it's a switch.
                if (result == BIT_TYPE_UNUSED) {
                    result = i;
                } else {
                    return BIT_TYPE_STRUCTURAL;
                }
            }
        }
    }
    return result;
}

bool SimpleInsnMap::isMapEquivalent(const SimpleInsnMap& otherMap) const {
    if (nBits != otherMap.nBits || nBitsUsed != otherMap.nBitsUsed) {
        return false;
    }
    for (size_t i = 0; i < nBitsUsed; ++i) {
        if (bitTypes[i] != otherMap.bitTypes[i] && 
            !(bitTypes[i] == BIT_TYPE_STRUCTURAL && otherMap.bitTypes[i] == BIT_TYPE_RESERVED) &&
            !(bitTypes[i] == BIT_TYPE_RESERVED && otherMap.bitTypes[i] == BIT_TYPE_STRUCTURAL)) {
            
            return false;
        }
    }
    return true;
}

void SimpleInsnMap::overrideBitType(size_t whichBit, BitType newType) {
    bitTypes[whichBit] = newType;
}

std::string SimpleInsnMap::toString() {
    std::stringstream ss;
    
    // Then, print out the bit types.
    for (size_t i = 0; i < nBits; i++) {
        ss << bitTypes[i];
    }

    std::string result;
    ss >> result;
    return result;
}
