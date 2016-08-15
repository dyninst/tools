
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

#include "Decoder.h"
#include "MappedInst.h"

Decoder dec_xed_x86_64 = Decoder(&xed_x86_64_decode, &xedInit, &xed_x86_64_norm, "xed", "x86_64");

Decoder dec_dyninst_x86_64 = Decoder(&dyninst_x86_64_decode, NULL, &dyninst_x86_64_norm, "dyninst", "x86_64");
Decoder dec_dyninst_aarch64 = Decoder(&dyninst_aarch64_decode, &dyninst_aarch64_init, &dyninst_aarch64_norm, "dyninst", "aarch64");

Decoder dec_gnu_x86_64 = Decoder(&gnu_x86_64_decode, NULL, &gnu_x86_64_norm, "gnu", "x86_64");
Decoder dec_gnu_aarch64 = Decoder(&gnu_aarch64_decode, NULL, &gnu_aarch64_norm, "gnu", "aarch64");

Decoder dec_llvm_x86_64 = Decoder(&llvm_x86_64_decode, &LLVMInit, &llvm_x86_64_norm, "llvm", "x86_64");

Decoder dec_llvm_aarch64 = Decoder(&llvm_aarch64_decode, &LLVMInit, &llvm_aarch64_norm, "llvm", "aarch64");

Decoder dec_null_x86_64 = Decoder(&null_x86_64_decode, NULL, &null_x86_64_norm, "null", "x86_64");

Decoder dec_null_aarch64 = Decoder(&null_aarch64_decode, NULL, &null_aarch64_norm, "null", "aarch64");

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
      assert((*initFunc)() != -1);
   }
   
   this->arch = arch;
   this->name = name;

   totalNormTime = 0;
   totalDecodeTime = 0;
   totalDecodedInsns = 0;
}

std::vector<Decoder> Decoder::getAllDecoders() {
   std::vector<Decoder> dec;
   dec.push_back(dec_llvm_x86_64);
   dec.push_back(dec_llvm_aarch64);
   dec.push_back(dec_gnu_x86_64);
   dec.push_back(dec_gnu_aarch64);
   dec.push_back(dec_dyninst_x86_64);
   dec.push_back(dec_dyninst_aarch64);
   dec.push_back(dec_xed_x86_64);
   dec.push_back(dec_null_aarch64);
   dec.push_back(dec_null_x86_64);
   return dec;
}

void Decoder::printAllNames(void) {
   std::vector<Decoder> allDecoders = getAllDecoders();
   for (int i = 0; i < allDecoders.size(); i++) {
      Decoder d = allDecoders[i];
      std::cout << "\t" << d.arch << ":\t" << d.name << "\n";
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

int Decoder::decode(char* inst, int nBytes, char* buf, int bufLen) {

   totalDecodedInsns++;

   struct timespec startTime;
   struct timespec endTime;

   clock_gettime(CLOCK_MONOTONIC, &startTime);
   int rc = func(inst, nBytes, buf, bufLen);
   clock_gettime(CLOCK_MONOTONIC, &endTime);

   totalDecodeTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                   (endTime.tv_nsec - startTime.tv_nsec);
   
   return rc;
}

const char* Decoder::getArch(void) {
   return arch;
}

const char* Decoder::getName(void) {
   return name;
}

int Decoder::getNumBytesUsed(char* inst, int nBytes) {
   MappedInst* mInst = new MappedInst(inst, nBytes, this, false);
   BitType* types = mInst->getBitTypes();
   int nUsed = mInst->getNumUsedBytes();
   delete mInst;
   return nUsed;
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

std::vector<Decoder> Decoder::getDecoders(char* arch, char* decNames) {

    if (arch == NULL) { 
        std::cout << "Error: No architecture specified. Exiting...\n";
        exit(1);
    }

    std::vector<Decoder> allDecoders = getAllDecoders();
    std::vector<Decoder> curDecoders = allDecoders;

    // Remove all decoders from different architectures.
    auto decode_iter = curDecoders.begin();
    for (;decode_iter != curDecoders.end();++decode_iter) {
        Decoder d = *decode_iter;
        if (strcmp(d.getArch(), arch)) {
            std::cout << "Removed decoder from " << d.getArch() << std::endl;
            decode_iter = curDecoders.erase(decode_iter);
        }
    }

    if (decNames == NULL) {
        return curDecoders;
    }

    std::vector<Decoder> result;
    std::vector<char*> names;
    char* decCopyBase = (char*)malloc(strlen(decNames) + 1);;

    // If the user specified decoders, we will make a copy and create an array
    // of strings instead by placing '\0' where commas were.

    // First, fill the new copy with the base string.
    char* decCopy = decCopyBase;
    strcpy(decCopy, decNames);
    names.push_back(decCopy);

    // Convert the single string into multiple with null delimiting.
    while (*decCopy) {
        if (*decCopy == ',') {
            *decCopy = 0;
            names.push_back(decCopy + 1);
        }
        decCopy++;
    }

    // Go through the decoders, adding each with a matching name.
    for (int i = 0; i < names.size(); i++) {
        for (int j = 0; j < curDecoders.size(); j++) {
            if (!strcmp(names[i], curDecoders[j].getName())) {
                result.push_back(curDecoders[j]);
            }
        }
    }

    // Clean up the copy that we made.
    free(decCopyBase);

    return result;
}
