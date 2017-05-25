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


#ifndef _DECODER_H_
#define _DECODER_H_

#define DECODING_BUFFER_SIZE 256
//#define EXPERIMENTAL_DECODERS

#include <vector>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

class Decoder {
public:
    Decoder(int (*decodeFunc)(char*, int, char*, int),
            int (*initFunc)(void),
            void (*normFunc)(char*, int),
            const char* name,
            const char* arch);
    int decode(char* inst, int nBytes, char* buf, int bufLen, bool shouldNorm);
    int decode(char* inst, int nBytes, char* buf, int bufLen);
    void normalize (char* buf, int bufLen);
    int getNumBytesUsed(char* inst, int nBytes);
    const char* getName(void);
    const char* getArch(void);
    void setNorm(bool newNorm);
    static void destroyAllDecoders(void);
    static Decoder* getDecoder(const char* arch, const char* decName);
    static std::vector<Decoder*> getAllDecoders(void);
    static std::vector<Decoder*> getDecoders(const char* arch, const char* names);
    static void printAllNames(void);
    unsigned long getTotalNormalizeTime(void);
    unsigned long getTotalDecodeTime(void);
    unsigned long getTotalDecodedInsns(void);
    const char* name;
    const char* arch;

    static void printErrorStatus();

private:

    void (*normFunc)(char*, int);
    int (*func)(char*, int, char*, int);

    bool norm;

    unsigned long totalDecodeTime;
    unsigned long totalNormTime;

    unsigned long totalDecodedInsns;

    static Decoder* curDecoder;
    static int curInsnLen;
    static char* curInsn;

    static std::vector<Decoder*> allDecoders;

};

#endif /* _DECODER_H_ */
