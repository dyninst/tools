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

#include <vector>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "Architecture.h"
#include "Normalization.h"

/*
 * The Decoder class is a combination of:
 *  1. A decode function that converts a buffer of bytes into an assembly language string
 *  2. A normalization function that converts the decoder-produced assembly language string
 *      into a form recognizable by an assembler.
 *  3. An initialization function that will be called before the decoder is ever called.
 *
 * Notes:
 *  There should be at most one decoder for each combination of architecture and name.
 *      (eg. Do NOT create two "x86_64" decoders both named "gnu".) This will probably not cause
 *      a crash, but which decoder is used will be undefined.
 *  Do NOT destroy decoders until the end of the program. Decoders will be passed as pointers
 *      through many different methods. Destroying decoders while Fleece is still testing them
 *      results in undefined and probably undesirable behavior.
 */
class Decoder {
public:
    
    /*
     * Constructs a Decoder given:
     *  decodeFunc: A pointer to a function with the following declaration:
     *      int decodeFunc(char* insnBytes, int nBytes, char* outputBuffer, int outputBufferLen);
     *      decodeFunc should return 0 on successful decoding, and any non-zero value on failure.
     *  initFunc: A pointer to a function that will be called before the decoder is used. This
     *      function should return 0 on success, non-zero on failure.
     *  normFunc: A pointer to a function with decoder-specific normalization. This function
     *      should take the assembly language string and the length of the buffer it is in.
     *  name: The name of the decoder library (eg. "llvm", "gnu", "xed", ...)
     *  arch: The name of the architecture whose instructions this decoder can decode
     *      (eg. "x86_64", "aarch64", ...)
     */
    Decoder(int (*decodeFunc)(char*, int, char*, int),
            int (*initFunc)(void),
            void (*normFunc)(char*, int),
            const char* name,
            const char* arch);

    /*
     * Two decode methods. The first method will normalize the output if shouldNorm is true.
     * the second method will normalize the output if the decoder is generally intended to
     * have its output normalized (this can be changed with Decoder::setNorm).
     */
    int decode(char* inst, int nBytes, char* buf, int bufLen, bool shouldNorm);
    int decode(char* inst, int nBytes, char* buf, int bufLen);

    /*
     * Applies normalization functions to the decoder's assembly language output in three steps:
     *  1. Generic normalization (like changing case, changing tabs to spaces)
     *  2. Architecture specific normalization (like changing "%st1" to "%st(1)" because the
     *      assembler only accepts the second form).
     *  3. Decoder specific normalization. This calls the normFunc() that was given as a
     *      parameter during decoder construction. It should generally be used to fix outputs
     *      that vary in a way that is unlikely to appear in other decoders.
     */
    void normalize (char* buf, int bufLen);
    
    /*
     * Accessors for basic decoder info.
     */
    const char* getName(void);
    const char* getArch(void);

    /*
     * Sets the general behavior of this decoder. If this is false, output will only be
     * normalized to created format strings. If this is true, output will be normalized for
     * all of the testing process (but none of the mapping process).
     */
    void setNorm(bool newNorm);

    /*
     * Returns a decoder with a given architecture and name. The behavior of this function is
     * undefined if multiple decoders are created for the same architecture with the same name.
     */
    static Decoder* getDecoder(const char* arch, const char* decName);

    /*
     * Returns a vector of Decoders from an architecture and a comma-separated list of names.
     */
    static std::vector<Decoder*> getDecoders(const char* arch, const char* names);
    
    /*
     * Prints all decoder names to stdout.
     */
    static void printAllNames(void);

    /*
     * Prints the currently active decoder and current input bytes to stderr. This should be
     * called in the case of a segfault or abort because it will show which decoder is
     * responsible and which input caused the issue.
     */
    static void printErrorStatus();

private:

    /*
     * Basic info identifying the decoder.
     */
    const char* name;
    const char* arch;

    /*
     * The normalization function called for decoder specific normalization.
     */
    void (*normFunc)(char*, int);

    /*
     * The decode function.
     */
    int (*func)(char*, int, char*, int);

    /*
     * If true, this decoder will normalize output before reassembly and reporting. If false, this
     * decoder will only normalize output to make format strings.
     */
    bool norm;

    /*
     * Used to keep track of which decoder is currently active so that it can be reported in case
     * of segfaults.
     */
    static Decoder* curDecoder;
    static int curInsnLen;
    static char* curInsn;
    
    /*
     * A vector of all decoder objects that have been created.
     */
    static std::vector<Decoder*> allDecoders;

};

#endif /* _DECODER_H_ */
