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

#include <assert.h>
#include <cstring>
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
}

bool signalsError(const char* token);

void removeFirst(char* buf, int bufLen, const char* str);

void removeTrailing(char* buf, int bufLen, const char* str);

void removeOperand(std::string& str, const std::string& op, const std::string& operand);

/*
 * Removes a substring of length <len> starting at the first character of the
 * first instance of <substr>.
 */
void removeAtSubStr(std::string& str, const std::string& substr, int len);

/*
 * Replaces a substring within a buffer.
 */
void replaceStr(char* buf, int bufLen, const char* oldStr, const char* newStr);

/*
 * Adds '0x' before each string of valid hex characters, except after a '*'
 * character.
 */
void prepend0x(std::string& str);

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

/*
 * Reads <nBytes> bytes from stdin and places them at the beginning of buf. No
 * bounds checking is done.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int getStdinBytes(char* buf, unsigned int nBytes);

/*
 * Returns the value of a hexidecimal character, so '0' = 0, '1' = 1, 'a' = 10,
 * 'A' = 10, and so on. This function does NOT check if the character is a
 * hexidecimal character, and the behavor is undefined if the input is not in
 * hexidecimal.
 */
int getCharHexVal(char c);

/*
 * Returns the hex equivalent of a character, so 0 = '0', 1 = '1', 10 = 'a',
 * and so on. Assumes the number is between 0 and 15 inclusively.
 */
char valToHex(int val);

/*
 * Fills the buffer buf with the string equivalent of the hex value shifted by
 * the shift amount.
 *
 * WARNING: This function makes no checks for validity of the hex string. The
 * string must contain ONLY the characters with hexidecimal values, not a
 * leading '0x' or other formatting.
 *
 * Returns 0 on success, -1 on failure.
 */
int shiftHex(char* hex, int shift, char* buf, int bufLen);

char negHex(char);

int getMinBits(long l);

void removeCharacter(char* buf, int bufLen, char c);

void writeStrToFile(const char* file, long offset, char* str);

void strStripDigits(char* str);
void strStripHex(char* str);
#endif /* _MYSTRING_H_ */
