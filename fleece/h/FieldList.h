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

#ifndef _FIELD_LIST_H_
#define _FIELD_LIST_H_

#include <assert.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "StringUtils.h"

/*
 * A list of null-terminated strings, constructed from an initial c-string. The
 * class itself does not support changing the number of fields or the field
 * pointers, but it does NOT protect against changing the values at the
 * pointers, which can be accessed by getField().
 */
class FieldList {

public:

    static unsigned long long totalHasErrTime;

    /*
     * Creates a list of space-delimited fields as a FieldList. The values are
     * copied, so the original buffer may be disposed of.
     */
    FieldList(const char* buf);

    /*
     * Deletes all fields, cleaning up the memory of the list.
     */
    ~FieldList();

    /*
     * Gives the number of fields in the list.
     */
    size_t size() const;

    /*
     * Returns true if the field list has the given field.
     */
    bool hasField(const char* field) const;
   
    /*
     * Returns a pointer to the null-terminated string stored at <index>
     * location in the list of fields.
     */
    const char* getField(size_t index) const;

    /*
     * Replaces the field at a given index with a new value. This value will be
     * copied from the supplied string.
     */
    void setField(size_t index, const char* newField);

    /*
     * Removes all digits from all fields. Each contiguous set of digits is
     * replaced with a pound sign ('#').
     */
    void stripDigits();
   
    /*
     * Removes all valid hex characters following "0x" is all of the fields.
     */
    void stripHex();

    /*
     * Returns the total number of bytes used in the fields (includes null
     * termination).
     */
    size_t getTotalBytes(void);

    /*
     * Fills the buffer with a character array representation of the fields. It
     * will null-terminate the buffer (at len), even if that means cutting off 
     * characters.
     */
    void fillBuf(char* buf, size_t len) const;

    /*
     * Returns true if one of the fields in the list appears to represent an
     * error in the disassembly.
     */
    bool hasError() const;

    /*
     * Returns true if the character is a separator character.
     */
    static bool isSeparator(char c);
   
    /*
     * Returns true if the given field is an immediate.
     */
    bool isFieldImm(size_t whichField);

    /*
     * Returns true if the given field is a register.
     */
    bool isFieldReg(size_t whichField);

    /*
     * Prints the field list as a set of fields and separators.
     */
    void print(FILE* f);

    /*
     * Prints the instruction that was used to construct this field list.
     */
    void printInsn(FILE* f);

private:

     /*
      * The number of fields in the list. This is one more than the number of 
      * separators.
      */
    size_t nFields;

    /*
     * An array of c-style strings, each representing a single field of an
     * instruction. Prefixes and opcodes are considered fields.
     */
    char** fields;

    /*
     * An array of c-style strings, each holding the characters between two
     * fields. Most commonly, separators are ", ", but they can be a string of
     * any characters in the list of separators.
     */
    char** separators;

    /*
     * Determines the number of fields in a c-string.
     */
    size_t detectNumFields(const char* buf);

    /*
     * Uses the value in nFields to allocate c-strings for the fields and separators.
     */
    void allocateFieldsAndSeparators();

    /*
     * Parses the string into fields and separators.
     */
    void initFieldsAndSeparators(const char* buf);

};
#endif /* _FIELD_LIST_H_ */
