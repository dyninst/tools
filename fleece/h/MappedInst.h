
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

#ifndef _MAPPEDINST_H_
#define _MAPPEDINST_H_

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

class MappedInst {
public:
    static unsigned long long t1;
    static unsigned long long t2;
    static unsigned long long totalQueueingTime;
    static unsigned long long totalLabellingTime;
    MappedInst(char* bytes, unsigned int nBytes, Decoder* dec);
    MappedInst(MappedInst* toCopy);
    ~MappedInst();
    FieldList* getFields() { return fields; }
    BitType    getBitType(size_t whichBit) const;
    size_t     getNumBytes() { return nBytes; }
    size_t     getNumBytesUsed() { return nBytesUsed; }
    char*      getRawBytes() { return bytes; }
    Decoder*   getDecoder() { return decoder; }
    void queueNewInsns(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc, std::vector<Decoder> decoders);
    
    struct insn_cmp {
        bool operator()(const MappedInst* a, const MappedInst* b) const {
            if (a->nBytes < b->nBytes) {
                return true;
            } else if (b->nBytes < a->nBytes) {
                return false;
            }

            for (size_t i = 0; i < a->nBytes * 8; i++) {
                if (a->getBitType(i) != b->getBitType(i)) {
                    if (a->getBitType(i) == BIT_TYPE_SWITCH) {
                        return true;
                    } else if (b->getBitType(i) == BIT_TYPE_SWITCH) {
                        return false;
                    }
                }
            }
            return false;
        }
    };
    static std::map<MappedInst*, MappedInst*, MappedInst::insn_cmp> uniqueMaps;
    static bool isByteOptional(Decoder* decoder, char* bytes, size_t nBytes, size_t whichByte, FieldList* oldFields);

    /*
     * Determines the minimum number of bytes in the instruction that result in the same decoding
     * as all of the bytes (any more bytes would be unnecessary).
     */
    static size_t findNumBytesUsed(char* bytes, size_t nBytes, Decoder* dec);

private:
    char* bytes;
    size_t nBytes;
    size_t nBytesUsed;
    bool isError;
    FieldList* fields;
    Decoder* decoder;
    SimpleInsnMap* map;
    void mapBitTypes();
    void deleteDownToNOptionalBytes(size_t numOptionalBytes);
    void trimUnusedEnd();
    void enqueueInsnIfNew(std::queue<char*>* queue, std::map<char*, int, StringUtils::str_cmp>* hc, std::vector<Decoder> decoders);
};

#endif /* _MAPPEDINST_H_ */
