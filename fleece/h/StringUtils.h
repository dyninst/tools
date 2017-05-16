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

#ifndef _MYSTRING_H_
#define _MYSTRING_H_

#define MAX_ERROR_FILENAME_LENGTH 32

#include <assert.h>
#include <cstring>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>


namespace StringUtils {
    struct str_cmp {
        bool operator()(const char* a, const char* b) const {
            return std::strcmp(a, b) < 0;
        }
    };
    
    struct str_eq {
        bool operator()(const char* a, const char* b) const {
            return std::strcmp(a, b) == 0;
        }
    };


    struct str_hash {
        std::size_t operator()(const char* k) const {
            return std::hash<std::string>()(std::string(k));
        }
    };
}

bool signalsError(const char* token);

void removeOperand(std::string& str, const std::string& op, const std::string& operand);

/*
 * Removes a substring of length <len> starting at the first character of the
 * first instance of <substr>.
 */
void removeAtSubStr(std::string& str, const std::string& substr, int len);

/*
 * Fills a buffer with <len> random bytes. No bounds checking is performed.
 * This function always returns 0 (it cannot fail).
 */
int randomizeBuffer(char* buf, unsigned int len);

/*
 * Flips a single bit within the provided buffer. The <whichBit> argument is
 * treated as an index into the buffer as an array of bits.
 */
void flipBufferBit(char* buf, int bit);

/*
 * Sets a single bit within the provided buffer. The <whichBit> argument is
 * treated as an index into the buffer as an array of bits.
 */
void setBufferBit(char* buf, int bit, int val);

/*
 * Prints the 0s and 1s of a buffer to standard output.
 */
void printBufferBits(char* buf, unsigned int len);

/*
 * Randomizes a vector of bits within the buffer. The position array <pos> must
 * contain <len> elements, each of which specifies which bit should recieve a
 * random value.
 */
void randomizeBufferBitVector(char* buf, unsigned int* pos, unsigned int len);

/*
 * Sets a vector of bits within the buffer. The position array <pos> must
 * contain <len> elements, each of which specifies which bit should recieve a
 * bit from <value>. The order bits are set is dictated by the order of the
 * <pos> argument. The values in the buffer will be:
 *
 * buf[pos[i]] = value[i]
 *
 * Where i runs from 0 to len - 1 (inclusively) and both buf and value are
 * treated as bit arrays.
 */
void setBufferBitVector(char* buf, unsigned int* pos, char* value, unsigned int len);

/*
 * Provides the value of a single bit in a buffer. No bounds checking is done.
 *
 * Returns 0 if the value at buf[bit] (with buffer as an array of bits) is 0.
 * Returns a non-zero value otherwise.
 */
unsigned char getBufferBit(char* buf, int bit);

void removeCharacter(char* buf, int bufLen, char c);

void strStripDigits(char* str);

void strStripHex(char* str);

std::string asmErrorToFilename(const char* asmError);

void printByteBuffer(std::ostream& stream, const char* bytes, int nBytes);
#endif /* _MYSTRING_H_ */
