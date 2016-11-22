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

#include <iostream>
#include "Assembly.h"

Assembly::Assembly(const Assembly& other) {
    Assembly(other.bytes, other.nBytes, other.decoder);
}

Assembly::Assembly(const char* bytes, size_t nBytes, Decoder* decoder) {
    
    decStr = NULL;
    templateStr = NULL;
    bytes = NULL;
    asmError = NULL;
    asmBytes = NULL;

    this->nBytes =nBytes;
    this->bytes = new char[nBytes];
    memcpy(this->bytes, bytes, nBytes);
    this->decoder = decoder;
}

Assembly::~Assembly() {
    invalidate();
    delete [] bytes;
}

const char* Assembly::getString() {
    if (decStr == NULL) {
        makeString();
    }
    return decStr;
}

const char* Assembly::getTemplate() {
    if (templateStr == NULL) {
        makeTemplate();
    }
    return templateStr;
}

const char* Assembly::getBytes() {
    return bytes;
}

size_t Assembly::getNBytes() {
    return nBytes;
}

const FieldList* Assembly::getFields() {
    if (fields == NULL) { 
        makeFieldList();
    }
    return fields;
}

char Assembly::getAsmResult() {
    if (asmError == NULL && asmBytes == NULL) {
        makeAsmResult();
    }
    return asmResult;
}

const char* Assembly::getAsmError() {
    if (asmError == NULL && asmBytes == NULL) {
        makeAsmResult();
    }
    return asmError;
}

const char* Assembly::getAsmBytes() {
    if (asmError == NULL && asmBytes == NULL) {
        makeAsmResult();
    }
    return asmBytes;
}

size_t Assembly::getNAsmBytes() {
    if (asmBytes == NULL) {
        makeAsmResult();
    }
    return nAsmBytes;
}

bool Assembly::isError() {
    if (decStr == NULL) {
        makeString();
    }
    return decError;
}

void Assembly::flipBit(size_t whichBit) {
    invalidate();
    flipBufferBit(bytes, whichBit);
}

void Assembly::setBit(size_t whichBit, int newValue) {
    invalidate();
    setBufferBit(bytes, whichBit, newValue);
}

void Assembly::makeString() {
    decStr = new char[DECODING_BUFFER_SIZE];
    decError = !decoder->decode(bytes, nBytes, decStr, DECODING_BUFFER_SIZE);
}

void Assembly::makeTemplate() {
    if (decStr == NULL) {
        makeString();
    }
    FieldList templateFields = FieldList(decStr);

    templateFields.stripHex();
    templateFields.stripDigits();
    Architecture::replaceRegSets(templateFields);

    size_t templateLen = templateFields.getTotalBytes();
    templateStr = new char[templateLen];
    templateFields.fillBuf(templateStr, templateLen);
}

void Assembly::makeAsmResult() {
    if (decStr == NULL) {
        makeString();
    }
    asmError = new char[REASM_ERROR_BUF_LEN];
    asmBytes = new char[Architecture::maxInsnLen];
    asmResult = reassemble(bytes, nBytes, decStr, NULL, REASM_FILENAME, 
            asmBytes, Architecture::maxInsnLen, (int*)&nAsmBytes, asmError, 
            REASM_ERROR_BUF_LEN);
}

void Assembly::makeFieldList() {
    if (decStr == NULL) {
        makeString();
    }
    fields = new FieldList(decStr);
}

void Assembly::invalidate() {
    if (decStr != NULL) {
        delete[] decStr;
        decStr = NULL;
    }
    if (templateStr != NULL) {
        delete[] templateStr;
        templateStr = NULL;
    }
    if (bytes != NULL) {
        delete[] bytes;
        bytes = NULL;
    }
    if (asmError != NULL) {
        delete[] asmError;
        asmError = NULL;
    }
    if (asmBytes != NULL) {
        delete[] asmBytes;
        asmBytes = NULL;
    }
    if (fields != NULL) {
        delete fields;
        fields = NULL;
    }
}
