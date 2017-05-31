
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

#ifndef _BITFIELD_H_
#define _BITFIELD_H_

#include <iostream>
#include <list>
#include "StringUtils.h"

/*
 * The Bitfield class is used to represent immediate values encoded directly in
 * an instruction. A Bitfield is constructed from the string representation of
 * an immediate (like "35" or "0x23"). The Bitfield class can then be used to
 * match the bits of this immediate to bits in a buffer.
 */
class Bitfield {
public:
    /*
     * Create a Bitfield from a hex or decimal string (eg "35" or "0x23")
     *
     * Returns NULL if the string could not be made into a bitfield
     * (it contained characters that were not hex or decimal).
     *
     * Note: this is not the constructor, but it is the only publically
     * exposed way to create a Bitfield because constructors cannot returm
     * null to signify an error.
     */
    static Bitfield* create(const char* str);

    /*
     * Destroys the Bitfield, freeing memory.
     */
    ~Bitfield();

    /*
     * Returns 0 if the bits in the buffer do not match the bit field. Returns
     * greater than 0 if nBits of the buffer match the Bitfield.
     */
    int matches(char* buf, int whichBit, int nBits);
private:

    /*
     * Constructs a Bitfield object. This function should NOT be called directly
     * because it creates a blank field with not possible encodings. The
     * constructor is not used for adding encoding values because handling
     * errors from constructors is painful (exceptions or validation methods
     * required).
     */
    Bitfield();

    /*
     * Adds a possible encoding value for this Bitfield.
     */
    void addPossibleEncodingValue(uint64_t val);

    /*
     * All possible encoding values for this Bitfield.
     */
    std::list<uint64_t>* vals;
};

#endif /* _BITFIELD_H_ */
