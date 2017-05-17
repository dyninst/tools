
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

#include "Mask.h"

static char* getPartialMask(const char* strMask, int maskLen, char symbol) {
    char* partMask = new char[maskLen];
    assert(partMask != NULL);
    bzero(partMask, maskLen);

    for (int i = 0; i < 8 * maskLen && strMask[i]; i++) {
        if (strMask[i] == symbol) {
            setBufferBit(partMask, i, 1);
        }
    }

    return partMask;
}

Mask::Mask(const char* strMask) {
    assert(strMask != NULL && *strMask && "NULL string mask!");

    maskLen = (strlen(strMask) + 7) / 8;
    setMask = getPartialMask(strMask, maskLen, MASK_SYMBOL_SET_BIT);
    clrMask = getPartialMask(strMask, maskLen, MASK_SYMBOL_CLR_BIT);
    incMask = getPartialMask(strMask, maskLen, MASK_SYMBOL_INC_BIT);
   
    incVal = new char[maskLen];
    assert(incVal != NULL);
    bzero(incVal, maskLen);
}

Mask::~Mask() {
    delete[] setMask;
    delete[] clrMask;
    delete[] incMask;
    delete[] incVal;
}

void Mask::increment(void) {
    char* cur = incVal + maskLen - 1;
    while (cur >= incVal && !(++(*cur))) {
        cur--;
    }
}

void Mask::apply(char* buf, int bufLen) {

    // Masks can only be applied to buffers of greater or equal length.
    assert(bufLen >= maskLen);
   
    // Handle setting and clearing.
    for (int i = 0; i < maskLen; i++) {
        buf[i] |= setMask[i];
        buf[i] &= ~clrMask[i];
    }

    // Handle the incremented value.
    int valBit = 8 * maskLen - 1;
    for (int i = 8 * maskLen - 1; i >= 0; i--) {
        if (getBufferBit(incMask, i)) {
            setBufferBit(buf, i, getBufferBit(incVal, valBit));
            valBit--;
        }
    }
}
