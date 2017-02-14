
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

    #ifdef COUNTING_OPCODE_COMBOS
    opcodeBit = new char[nBits * sizeof(*opcodeBit)];
    bcopy(toCopy->opcodeBit, opcodeBit, nBits * sizeof(*opcodeBit));
    #endif
}

SimpleInsnMap::SimpleInsnMap(const char* bytes, size_t nBytes, size_t nBytesUsed, Decoder* dec) {
    
    nBits = 8 * nBytes;
    nBitsUsed = 8 * nBytesUsed;
    bitTypes = new BitType[nBits * sizeof(*bitTypes)];
    confirmedImm = new bool[nBits * sizeof(*confirmedImm)];
    for (size_t i = 0; i < nBits; i++) {
        confirmedImm[i] = false;
    }
    
    #ifdef COUNTING_OPCODE_COMBOS
    opcodeBit = new char[nBits * sizeof(*opcodeBit)];
    for (size_t i = 0; i < nBits; ++i) {
        opcodeBit[i] = 107;
    }
    #endif

    char tmpBytes[nBytes];
    bcopy(bytes, tmpBytes, nBytes);
    mapBitTypes(tmpBytes, dec);
}

SimpleInsnMap::~SimpleInsnMap() {
    delete [] bitTypes;
    delete [] confirmedImm;

    #ifdef COUNTING_OPCODE_COMBOS
    delete [] opcodeBit;
    #endif
}

/*
size_t SimpleInsnMap::determineOpcodeField(const char* bytes, Decoder* dec) {
    size_t result = 0; 
    char decStr[DECODING_BUFFER_SIZE];
    decoder->decode(bytes, nBytes, decStr, DECODING_BUFFER_SIZE);
    FieldList fields = FieldList(decStr);
    return Architecture::getOpcodeField(startFields);
}
*/

void SimpleInsnMap::mapBitTypes(char* bytes, Decoder* dec) {
    bool success = false;
    char decStr[DECODING_BUFFER_SIZE];
    int consecutiveUnused = 0;

    bool isError = (bool)dec->decode(bytes, nBits / 8, decStr, DECODING_BUFFER_SIZE);
    FieldList startFields = FieldList(decStr);
    #ifdef DEBUG_SIMPLE_MAP
    std::cout << "Starting insn = " << decStr << "\n";
    for (size_t j = 0; j < nBits / 8; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)bytes[j] << " ";
    }
    std::cout << std::dec << "\n";
    #endif
    
    #ifdef COUNTING_OPCODE_COMBOS
    const char* startOpcode = Architecture::getOpcode(startFields);
    #ifdef DEBUG_SIMPLE_MAP
    std::cout << "Starting opcode = " << startOpcode << "\n";
    #endif
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
    for (i = 0; consecutiveUnused < CONSECUTIVE_UNUSED_THRESHOLD && i < nBitsUsed; i++) {
        #ifdef DEBUG_SIMPLE_MAP
        std::cout << std::setfill('0') << std::setw(2) << i << ": ";
        #endif

        if (confirmedImm[i]) {
            #ifdef DEBUG_SIMPLE_MAP
            std::cout << decStr << " (field " << bitTypes[i] << " C) \n";
            #endif

            #ifdef COUNTING_OPCODE_COMBOS
            opcodeBit[i] = 0; //false;
            #endif

            continue;
        }
        flipBufferBit(bytes, i);
        success = !dec->decode(bytes, nBits / 8, decStr, DECODING_BUFFER_SIZE);
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
        std::cout << std::dec << "): " << decStr;
        #endif
    
        #ifdef COUNTING_OPCODE_COMBOS
        opcodeBit[i] = (success && strcmp(startOpcode, Architecture::getOpcode(newFields)) != 0);
        #ifdef DEBUG_SIMPLE_MAP
        std::cout << "(opcode = " << (opcodeBit[i] == true ? "1" : "0")  << ")";
        #endif
        #endif

        #ifdef DEBUG_SIMPLE_MAP
        std::cout << "\n";
        #endif

        // Default the bit type to unused.
        bitTypes[i] = BIT_TYPE_UNUSED;
        if (success && !newFields.hasError()) {
            bitTypes[i] = getBitTypeByChanges(startFields, newFields);

            if (bitTypes[i] >= 0) {

                Bitfield* bf = bitfields[bitTypes[i]];
                if (bf != NULL) {
                    flipBufferBit(bytes, i); 
               
                    int matchLen = bf->matches(bytes, i, nBitsUsed);
                    if (matchLen > 0) {
                        Bitfield* newBf = Bitfield::create(newFields.getField(bitTypes[i]));
                        flipBufferBit(bytes, i);
                        if (newBf != NULL) {
                            int newMatchLen = newBf->matches(bytes, i, nBitsUsed);
                            if (newMatchLen == matchLen) {
                                
                                #ifdef DEBUG_SIMPLE_MAP
                                std::cout << "Matched " << matchLen << " bits at bit " << i << "\n";
                                std::cout << "\t" << decStr << " (field " << bitTypes[i] << ")\n";
                                #endif
                                
                                confirmedImm[i] = true;
                                for (int j = 1; j < matchLen; j++) {
                                    confirmedImm[i + j] = true;
                                    bitTypes[i + j] = bitTypes[i];
                                }
                            }
                        }
                    } else {
                        flipBufferBit(bytes, i);
                    }
                }
            }
        } else {
            bitTypes[i] = BIT_TYPE_CAUSED_ERROR;
            if (isError) {
                bitTypes[i] = BIT_TYPE_UNUSED;
            } else {
                bitTypes[i] = BIT_TYPE_CAUSED_ERROR;
            }
        }

        consecutiveUnused++;
        if (bitTypes[i] != BIT_TYPE_UNUSED) {
            consecutiveUnused = 0;
        }
        flipBufferBit(bytes, i);
    }

    // If we didn't make it to the end of the string, it was unused, so mark all
    // remaining bits unused.
    while (i < nBits) {
        #ifdef COUNTING_OPCODE_COMBOS
        opcodeBit[i] = false;
        #endif
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
        return BIT_TYPE_SWITCH;
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
                    return BIT_TYPE_SWITCH;
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
        if (bitTypes[i] != otherMap.bitTypes[i]) {
            if (bitTypes[i] == BIT_TYPE_SWITCH && otherMap.bitTypes[i] == BIT_TYPE_CAUSED_ERROR) {
            } else if (bitTypes[i] == BIT_TYPE_CAUSED_ERROR &&
                otherMap.bitTypes[i] == BIT_TYPE_SWITCH) {
            //} else if (isError && bitTypes[k] == BIT_TYPE_SWITCH &&
            //    tmpBitTypes[k] == BIT_TYPE_UNUSED) {
            //} else if (isError && bitTypes[k] == BIT_TYPE_UNUSED &&
            //    tmpBitTypes[k] == BIT_TYPE_SWITCH) {
            } else {
                return false;
            }
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
