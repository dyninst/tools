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

#include <assert.h>
#include <iomanip>
#include <iostream>
#include "Decoder.h"
    
std::vector<Decoder*> Decoder::allDecoders;
Decoder* Decoder::curDecoder;
int Decoder::curInsnLen;
char* Decoder::curInsn;

void Decoder::printErrorStatus() {
    if (curDecoder == NULL) {
        std::cerr << "Not currently decoding\n";
        return;
    }

    std::cerr << "Current insn = (" << curInsnLen << " bytes): ";
    for (int j = 0; j < curInsnLen; j++) {
        std::cerr << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)curInsn[j] << " ";
    }
    std::cerr << "Current decoder = " << curDecoder->name << " " 
              << curDecoder->arch << "\n";
    std::cerr << "\n" << std::dec;
}

Decoder::Decoder(
        int (*decodeFunc)(char*, int, char*, int),
        int (*initFunc)(void),
        void (*normFunction)(char*, int),
        const char* name,
        const char* arch) {
 
    func = decodeFunc;
    normFunc = normFunction;
    
    // Execute any initialization required for this decoder.
    if (initFunc != NULL) {
        int rc = (*initFunc)();
        if (rc != 0) {
            std::cerr << "Error: Could not initialize decoder: " << arch << ":" << name << std::endl;
            exit(-1);
        }
    }
    
    this->arch = arch;
    this->name = name;
 
    norm = false;
    totalNormTime = 0;
    totalDecodeTime = 0;
    totalDecodedInsns = 0;
    allDecoders.push_back(this);
}

void Decoder::destroyAllDecoders()
{
    for (auto it = allDecoders.begin(); it != allDecoders.end(); ++it) {
        delete *it;
    }
}

std::vector<Decoder*> Decoder::getAllDecoders() {
    return allDecoders;
}

void Decoder::printAllNames(void) {
    std::vector<Decoder*> allDecoders = getAllDecoders();
    for (size_t i = 0; i < allDecoders.size(); i++) {
        Decoder* d = allDecoders[i];
        std::cout << "\t" << d->arch << ":\t" << d->name << "\n";
    }
}

void Decoder::normalize(char* buf, int bufLen) {

    struct timespec startTime;
    struct timespec endTime;

    clock_gettime(CLOCK_MONOTONIC, &startTime);

    normFunc(buf, bufLen);
    clock_gettime(CLOCK_MONOTONIC, &endTime);

    totalNormTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                  (endTime.tv_nsec - startTime.tv_nsec);
}


int Decoder::decode(char* inst, int nBytes, char* buf, int bufLen, bool shouldNorm) {
    
    curDecoder = this;
    curInsnLen = nBytes;
    curInsn = inst;

    totalDecodedInsns++;

    struct timespec startTime;
    struct timespec endTime;

    clock_gettime(CLOCK_MONOTONIC, &startTime);
    *buf = 0;
    int rc = func(inst, nBytes, buf, bufLen);
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    totalDecodeTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                   (endTime.tv_nsec - startTime.tv_nsec);
 
    curDecoder = NULL;

    if (!strcmp(buf, "")) {
        strncpy(buf, "empty_decoding", bufLen);
    }
    
    if (shouldNorm) {
        normalize(buf, bufLen);
    }

    return rc;
}
int Decoder::decode(char* inst, int nBytes, char* buf, int bufLen) {
    return decode(inst, nBytes, buf, bufLen, norm);
}

const char* Decoder::getArch(void) {
    return arch;
}

const char* Decoder::getName(void) {
    return name;
}

unsigned long Decoder::getTotalDecodeTime() {
    return totalDecodeTime;
}

unsigned long Decoder::getTotalNormalizeTime() {
    return totalNormTime;
}

unsigned long Decoder::getTotalDecodedInsns() {
    return totalDecodedInsns;
}

void Decoder::setNorm(bool newNorm) {
    norm = newNorm;
}

Decoder* Decoder::getDecoder(const char* arch, const char* decName) {
    std::cout << "Getting decoder " << decName << " for " << arch << "\n";
    for (auto it = allDecoders.begin(); it != allDecoders.end(); ++it) {
        Decoder* cur = *it;
        if (!strcmp(cur->getName(), decName) && !strcmp(cur->getArch(), arch)) {
            std::cout << "Found decoder\n";
            return cur;
        }
    }
    std::cout << "Could not find decoder\n";
    return NULL;
}

std::vector<Decoder*> Decoder::getDecoders(const char* arch, const char* decNames) {

    assert(arch && decNames);

    std::vector<Decoder*> decoders = std::vector<Decoder*>();

    size_t decCopyLen = strlen(decNames);
    char decCopyBuf[decCopyLen + 1];
    char* decCopyBase = &(decCopyBuf[0]);
    memset(decCopyBase, 0, decCopyLen + 1);
    strncpy(decCopyBase, decNames, decCopyLen); 

    char* decCopyStart = decCopyBase;
    for(;*decCopyBase;decCopyBase++)
    {
        if(*decCopyBase == ',')
        {
            *decCopyBase = 0;
            Decoder* cur = getDecoder(arch, decCopyStart);
            if (cur != NULL) {
                decoders.push_back(cur);
            }
            decCopyStart = decCopyBase + 1;
        }
    }

    /* The last arg will not have a comma to terminate */
    Decoder* cur = getDecoder(arch, decCopyStart);
    if (cur != NULL) {
        decoders.push_back(cur);
    }

    /* Return the filtered list of decoders */
    return decoders;
}
