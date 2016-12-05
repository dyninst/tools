/**
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

#ifndef _ASSEMBLY_H_
#define _ASSEMBLY_H_

#include <assert.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "Decoder.h"
#include "FieldList.h"
#include "Reassemble.h"
#include "StringUtils.h"

class Assembly {
public:
    Assembly(const Assembly& other);
    Assembly(const char* bytes, size_t nBytes, Decoder* decoder);
    ~Assembly();
    bool isEquivalent(Assembly* other);
    const char* getString();
    const char* getTemplate();
    const char* getBytes();
    size_t getNBytes();
    const FieldList* getFields();
    char getAsmResult();
    const char* getAsmError();
    const char* getAsmBytes();
    size_t getNAsmBytes();
    bool isError();

    void flipBit(size_t whichBit);
    void setBit(size_t whichBit, int newValue);

private:
    bool decError;

    char* decStr;
    char* templateStr;
    char* bytes;
    size_t nBytes;

    Decoder* decoder;
    FieldList* fields;
    
    char asmResult;
    char* asmError;
    char* asmBytes;
    size_t nAsmBytes;

    bool isReasmEqual(Assembly* other);
    void makeString();
    void makeTemplate();
    void makeAsmResult();
    void makeFieldList();
    void invalidate();
};

#endif // _ASSEMBLY_H_
