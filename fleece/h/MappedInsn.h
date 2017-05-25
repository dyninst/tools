
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

#ifndef _MAPPEDINSN_H_
#define _MAPPEDINSN_H_

#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "Architecture.h"
#include "Bitfield.h"
#include "BitTypes.h"
#include "Decoder.h"
#include "FieldList.h"
#include "Options.h"
#include "StringUtils.h"
#include "SimpleInsnMap.h"

class Decoder;

/*
 * The MappedInsn object encloses instruction bytes, a SimpleInsnMap and the
 * assembly language result as a FieldList. MappedInsns can be used to generate
 * new instructions through the queueNewInsns() method, which mutates the
 * original instruction based on its detected structure.
 */
class MappedInsn {

public:
    
    /*
     * Create a MappedInsn structure from a sequence of bytes and a decoder.
     */
    MappedInsn(char* bytes, unsigned int nBytes, Decoder* dec);

    /*
     * Destroys the MappedInsn, freeing memory.
     */
    ~MappedInsn();

    /*
     * Accessors for simple data.
     */
    FieldList*  getFields() { return fields; }
    BitType     getBitType(size_t whichBit) const;
    size_t      getNumBytes() { return nBytes; }
    size_t      getNumBytesUsed() { return nBytesUsed; }
    const char* getRawBytes() { return bytes; }
    Decoder*    getDecoder() { return decoder; }

    /*
     * This enqueues new byte sequences of Architecture::maxInsnLen into the queue
     * if these instructions have formats not already present in the std::map hc.
     * If an instruction is added to the queue, the vector of decoders is used to
     * record the format string according to each decoder (so that another decoder
     * doesn't report the same instruction as new if it decodes that instruction
     * in a way that produces a different format string).
     */
    void queueNewInsns(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc,
        std::vector<Decoder*> decoders);

    /*
     * Returns true if removing the byte at position whichByte of the instruction will result in an
     * instruction with the same decoding or a subset of the original fields.
     */
    static bool isByteOptional(Decoder* decoder, char* bytes, size_t nBytes, size_t whichByte, FieldList* oldFields);

    /*
     * Determines the minimum number of bytes in the instruction that result in the same decoding
     * as when all of the bytes are decoded.
     */
    static size_t findNumBytesUsed(char* bytes, size_t nBytes, Decoder* dec);

private:

    /*
     * A buffer containing the byte sequence that this MappedInsn is baed on.
     */
    char* bytes;

    /*
     * The number of bytes used to create this MappedInsn. This may be longer
     * than the number of bytes actually used in an instruction (for example,
     * a 1 byte pop instruction in x86 may have been decoded from a buffer of
     * 15 bytes). Usually, this number is equal to Architecture::maxInsnLen.
     */
    size_t nBytes;

    /*
     * The number of bytes actually used when decoding this instruction.
     */
    size_t nBytesUsed;

    /*
     * True if the bytes used to produce this MappedInsn were not a valid
     * instruction according to the decoder used.
     */
    bool isError;

    /*
     * The fields of assembly language that resulted from decoding the input
     * bytes.
     */
    FieldList* fields;

    /*
     * The decoder used when mapping the input bytes and generating new inputs.
     */
    Decoder* decoder;

    /*
     * A SimpleInsnMap containing the labels given to each of the input bits.
     */
    SimpleInsnMap* map;

    /*
     * Internal function used to instantiate the SimpleInsnMap and update the
     * preliminary bit types if necessary.
     */
    void mapBitTypes();

    /*
     * If this MappedInsn (which is usually a mutated version of the original
     * when this is called) has a format string that is not a key in the map
     * seenFormats, then the instruction will be add to the queue, and the
     * format string of the instruction according to each decoder in decoders
     * will be added to the seenFormats map.
     */
    void enqueueInsnIfNew(std::queue<char*>* queue, 
        std::map<char*, int, StringUtils::str_cmp>* seenFormats,
        std::vector<Decoder*> decoders);
};

#endif /* _MAPPEDINSN_H_ */
