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
#include <iomanip>
#include <iostream>
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

/*
 * This class provides access to relevant information based on the assembly language output of a
 * decoder. This class should be constructed by providing the input bytes for a decoder and the
 * decoder.
 *
 * This class uses delayed evaluation to return data. This means that data
 * members are not created until they are accessed. This is used because some
 * Assembly objects are only needed for templates, while others may be used
 * in reassembly, and it would be wasteful to construct all data values for
 * all assembly objects.
 */
class Assembly {
public:
    /*
     * Copy constructor. This will copy any of the results of delayed
     * evaluation so that the work isn't re-done later.
     */
    Assembly(const Assembly& other);

    /*
     * Creates an Assembly object given the input instruction and a decoder
     * that can provide the assembly language form of the instruction.
     */
    Assembly(const char* bytes, size_t nBytes, Decoder* decoder);

    /*
     * Destroys an Assembly object, freeing memory.
     */
    ~Assembly();

    /*
     * Checks whether or not two Assembly objects appear to encode the same
     * instruction based on the results of decoding.
     *
     * Returns true iff any of the following are true:
     *  - the input bytes of both assembly objects decoded as invalid bytes
     *  - the assembly language strings are identical after normalization
     *  - the assembly language strings reassemble to the identical bytes
     */
    bool isEquivalent(Assembly* other);

    /*
     * Returns the assembly language decoding of the input bytes as a c-string.
     */
    const char* getString();

    /*
     * Returns the template of the decoding as a c-string.
     */
    const char* getTemplate();

    /*
     * Returns the input bytes of the instruction.
     */
    const char* getBytes();
    size_t getNBytes();

    /*
     * Returns a FieldList for the assembly language decoding.
     */
    const FieldList* getFields();

    /*
     * Returns the result of reassembling an instruction.
     */
    char getAsmResult();
    const char* getAsmError();
    const char* getAsmBytes();
    size_t getNAsmBytes();

    /*
     * Returns true if the decoder returned an error code for the input bytes,
     * or produced an assembling language string indicating that the input
     * bytes were not a valid instruction.
     */
    bool isError();

    /*
     * Prints debug info to stdout.
     */
    void printDebug();
private:
    
    /*
     * The input bytes and their length.
     */
    char* bytes;
    size_t nBytes;

    /*
     * The result of decoding the input bytes.
     *
     * This value is created by delayed evaluation, so it will only be filled
     * once an accessor has been called that depends on this value.
     */
    bool decError;
    char* decStr;

    /*
     * The template string (format string) for this instruction.
     *
     * Created by delayed evaluation.
     */
    char* templateStr;

    /*
     * The decoder used to create this Assembly object.
     */
    Decoder* decoder;

    /*
     * The assembly language output of the decoder broken into a list of
     * fields.
     *
     * Created by delayed evaluation.
     */
    FieldList* fields;
    
    /*
     * The result of reassembly.
     *
     * Created by delayed evaluation.
     */
    char asmResult;
    char* asmError;
    char* asmBytes;
    size_t nAsmBytes;

    /*
     * Returns true if the result of reassembly is equal for two Assembly
     * objects.
     */
    bool isReasmEqual(Assembly* other);

    /*
     * The delayed evaluation code.
     */
    void makeString();
    void makeTemplate();
    void makeAsmResult();
    void makeFieldList();
};

#endif // _ASSEMBLY_H_
