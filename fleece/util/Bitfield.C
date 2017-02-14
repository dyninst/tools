
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

#include "Bitfield.h"

Bitfield* Bitfield::create(const char* str) {
   
    unsigned long long int val;
    char* endPtr;

    // First, try to create a decimal number.
    val = strtoull(str, &endPtr, 10);
    if (endPtr != '\0') {
    }
    bool found = (*endPtr == '\0');

    // If the nubmer wasn't decimal, try hex.
    if (!found) {
        val = strtoull(str, &endPtr, 16);
    }

    // Verify that the whole string was used.
    found = found || (*endPtr == '\0');

    // If the string was neither a decimal nor a hex number, don't create a
    // bitfield from it.
    if (!found) {
        return NULL;
    }

    // If the string was a number, create a bitfield and add this as a possible
    // encoding value.
    Bitfield* bf = new Bitfield();
    bf->addPossibleEncodingValue(val);
    return bf;
}  

void Bitfield::addPossibleEncodingValue(uint64_t val) {
    vals->push_back(val);
}

Bitfield::Bitfield() {
    vals = new std::list<uint64_t>();
}


Bitfield::~Bitfield() {
    delete vals;
}

int getValMatchLen(uint64_t val, char* bytes, int whichBit, 
        int nBits) {

    /*
    std::cout << "Finding match for field: " << val << "\n";
    std::cout << "Val = ";
    for (size_t i = 1; i <= 64; ++i) {
        if (val & ((uint64_t)0x1 << (64 - i))) {
            std::cout << "1";
        } else {
            std::cout << "0";
        }
    }
    std::cout << "\n";
    
    std::cout << "Imm = ";
    for (size_t i = 0; i < 64 - nBits + whichBit; ++i) {
        std::cout << " ";
    }
    for (size_t i = 0; i < nBits - whichBit; ++i) {
        if (getBufferBit(bytes, whichBit + i)) {
            std::cout << "1";
        } else {
            std::cout << "0";
        }
    }
    std::cout << "\n";
    */

    // Determine if the highest order bit is 1.
    bool topValIsOne = (val & ((uint64_t)0x1 << 63));

    // We need the index of the first bit that is flipped because this will
    // tell us where to start matching the output value to the input value.
    //
    // 0000000000000001001011101
    //                ^
    //                |---------- We are looking for this bit position.
    int firstFlip = 62;
    while (firstFlip > 0 && (bool)(val & ((uint64_t)0x1 << firstFlip)) == 
            topValIsOne) {
        firstFlip--;
    }
    
    // Determine how many bits from the input bytes match with the integer
    // value of this bit field.

    // First, match bits before the the first bit flip.
    //
    // Bytes:          0000001001011101 01011011101101001000
    // Value: 0000000000000001001011101
    //                 ^^^^^^
    // We are matching these bits.
    int nMatched = 0;
    while (whichBit + nMatched < nBits &&
            (bool)getBufferBit(bytes, whichBit + nMatched) == topValIsOne) {
        
        nMatched++;
    }

    // Start matching bits after the first bit flip.
    //
    // Bytes:          0000001001011101 01011011101101001000
    // Value: 0000000000000001001011101
    //                       ^^^^^^^^^^
    // We are matching these bits.
    int curShift = firstFlip;
    while (whichBit + nMatched < nBits && curShift >= 0 && 
            ((bool)getBufferBit(bytes, whichBit + nMatched) == 
            (bool)(val & ((uint64_t)0x1 << curShift)))) {

        nMatched++;
        curShift--;
    }

    // If we matched all the way to the last bit, return how many bits matched.
    //
    // Bytes:          0000001001011101 01011011101101001000
    // Value: 0000000000000001001011101
    //                 |--------------|
    // We are returning this length.
    if (curShift == -1) {
        return nMatched;
    }
    return 0;
    
    // Below code returns matches of incorrect length.
    /*
    // Here, we match bits even if the endianness of the value and the bytes
    // are different.
    for (int i = 0; i < nBits - whichBit && 8 * i < firstFlip; i++) {
        for (int j = 7; j >= 0; j--) {
            if ((bool)getBufferBit(bytes, whichBit + nMatched) == 
                (bool)(val & ((uint64_t)0x1 << (8 * i + j)))) {

                nMatched++;
            } else {
                return 0;
            }
        }
    }
  
    std::cout << "nBits = " << nBits << ", whichBit = " << whichBit << "\n";
    return nMatched;
    */
}

int Bitfield::matches(char* bytes, int whichBit, int nBits) {
 
    // Compare the bytes of the bitfield to all possible values that the bits
    // could represent.
    for (auto it = vals->begin(); it != vals->end(); ++it) {
        int matchLen = getValMatchLen(*it, bytes, whichBit, nBits);
        if (matchLen != 0) {
            return matchLen;
        }
    }
    
    return 0;
}
