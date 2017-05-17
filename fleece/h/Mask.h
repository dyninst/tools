
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

#ifndef _MASK_H_
#define _MASK_H_

#include <iomanip>
#include <iostream>
#include "StringUtils.h"

#define MASK_SYMBOL_SET_BIT '1'
#define MASK_SYMBOL_CLR_BIT '0'
#define MASK_SYMBOL_INC_BIT 'n'

/*
 * A Mask object can be applied to a buffer of bytes to set, clear and increment
 * combinations of bits. Masks are constructred from strings containing the
 * MASK_SYMBOL values defined above.
 *
 * Example usage:
 *
 * Mask m = 
 *   Mask("11110000nnnnxxxx")
 * m.apply(0100011110101110)
 * result: 1111000000001110
 *
 * Each character of the mask containing a '1' signifies a bit of the output
 * should be set to 1. Each character of the mask containing a '0' signifies a
 * bit of the output that should be set to 0. Each character of the mask
 * containing an 'n' signifies a bit of the output that should be set based
 * on the current increment value of the mask (initially 0). All other
 * characters in the mask indicate bits that should be unchanged.
 *
 * Example of incrementing a mask:
 *
 * Mask m = 
 *   Mask("1111nnnn")
 * m.apply(01000111)
 * result: 11110000
 *
 * m.increment()
 * m.apply(01000111)
 * result: 11110001
 *
 * m.increment()
 * m.apply(01000111)
 * result: 11110010
 */
class Mask {

public:

    /*
     * Construct a Mask object from a string. Each character of the string
     * determines how a single bit of a buffer will be changed when the mask is
     * applied.
     */
    Mask(const char* strMask);

    /*
     * Destroys the mask object, freeing memory.
     */
    ~Mask();

    /*
     * Increments the value applied to bits marked with MASK_SYMBOL_INC_BIT.
     * If the value is at its maximum (for example, a mask with 8 increment
     * bits with a value of 255), the value will be reset to 0.
     */
    void increment(void);

    /*
     * Applies the mask to a buffer of the given length.
     */
    void apply(char* buf, int bufLen);

private:

    /*
     * A buffer whose bytes can be ORed with an input buffer to set all bits
     * that should be 1.
     */
    char* setMask;

    /*
     * A buffer whose bytes can be NANDed with an input buffer to clear all bits
     * that should be 0.
     */
    char* clrMask;

    /*
     * Each bit in this buffer that contains a 1 will be changed in the input
     * buffer to reflect 1 bit of the increment value.
     */
    char* incMask;

    /*
     * The value (as a collection of bytes) that should be placed into the
     * input buffer where the increment mask contains 1s.
     */
    char* incVal;

    /*
     * The length of the mask in bytes.
     */
    int maskLen;

};

#endif /* _MASK_H_ */
