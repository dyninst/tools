
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

#ifndef _SIMPLE_INSN_MAP_H_
#define _SIMPLE_INSN_MAP_H_

#ifndef CONSECUTIVE_UNUSED_THRESHOLD
#define CONSECUTIVE_UNUSED_THRESHOLD 256
#endif

#define COUNTING_OPCODE_COMBOS

#include <iomanip>
#include <iostream>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include "Architecture.h"
#include "Bitfield.h"
#include "BitTypes.h"
#include "Decoder.h"
#include "FieldList.h"
#include "StringUtils.h"

class Decoder;

class SimpleInsnMap {

public:

    /*
     * Make a copy of a SimpleInsnMap from a pointer.
     */
    SimpleInsnMap(SimpleInsnMap* toCopy);

    /*
     * Returns a new SimpleInsnMap created from the given bytes and the given decoder.
     */
    SimpleInsnMap(const char* bytes, size_t nBytes, size_t nBytesUsed, Decoder* decoder);

    /*
     * Destroys a SimpleInsnMap.
     */
    ~SimpleInsnMap();

    /*
     * Returns an array of boolean values. A value at index i is true if bit i has been confirmed
     * to be a part of an immediate by matching the value in the binary to the value produced by
     * the decoder.
     */
    bool isBitConfirmedImm(size_t whichBit) { return confirmedImm[whichBit]; }

    /*
     * Returns the BitType associated with a bit at a given position. See BitType.h for the enum.
     */
    BitType getBitType(size_t whichBit) { return bitTypes[whichBit]; }

    /*
     * Returns true if two SimpleInsnMaps are considered equivalent. This is not the same as equal.
     * Maps may be equivalent but not equal if:
     *
     * 1. A bit is unused in an error and an error for another isnstruction.
     */
    bool isMapEquivalent(const SimpleInsnMap& otherMap) const;

    /*
     * Sets the bit type at index whichBit to newType. This method is called override instead of
     * set because the bits of a simple map are already set to a reasonable value; however, new
     * information about the instruction from a higher level of abstraction may override the inital
     * simple mapping.
     */
    void overrideBitType(size_t whichBit, BitType newType);

    #ifdef COUNTING_OPCODE_COMBOS
    /*
     * Returns true if a change in the bit whichBit caused a change in the opcode. If changing bit
     * whichBit resulted in an error, this method returns false.
     */
    char isOpcodeBit(size_t whichBit) { return opcodeBit[whichBit]; }
    #endif

    /*
     * Returns the number of bytes used in the instruction.
     */
    size_t getNumBytesUsed() { return 8 * nBitsUsed; }

    /*
     * Returns a string representation of the map.
     */
    std::string toString();

private:

    /*
     * The array of BitTypes, one for each bit.
     */
    BitType* bitTypes;

    /*
     * The number of bits in this SimpleInsnMap.
     */
    size_t nBits;

    /*
     * An array of boolean values. confirmedImm[i] == true implies that bit i appears in an
     * immedate whose value in the decoding was matched to bits in the instruction, which makes it
     * highly likely that the bit is a part of the immediate is has been attributed to.
     */
    bool* confirmedImm;

    /*
     * The minimum number of leading bytes in the instruction required to produce them same output
     * as all of the bytes in the instruction.
     */
    size_t nBitsUsed;

    #ifdef COUNTING_OPCODE_COMBOS
    /*
     * An array of boolean values. opcodeBit[i] == true implies that bit i changes the opcode of
     * the instruction when flipped.
     */
    char* opcodeBit;
    #endif

    /*
     * Determines the BitType for each bit of an instruction. This method is only called internally
     * after the number of bits and instruction has been set.
     */
    void mapBitTypes(char* bytes, Decoder* dec);

    /*
     * Determines the minimum number of bytes in the instruction that result in the same decoding
     * as all of the bytes (any more bytes would be unnecessary).
     */
    //size_t SimpleInsnMap::findNumBytesUsed(const char* bytes, size_t nBytes, Decoder* dec) {
};

#endif /* _SIMPLE_INSN_MAP_H_ */
