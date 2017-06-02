
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

#ifdef __cplusplus
extern "C" {
#include "xed-interface.h"
}
#else
#include "xed-interface.h"
#endif

#include <iomanip>
#include <iostream>
#include "Decoder.h"
#include "Normalization.h"
#include "StringUtils.h"

#define XED_MACHINE_MODE XED_MACHINE_MODE_LONG_64
#define XED_ADDRESS_WIDTH XED_ADDRESS_WIDTH_64b

#define FIND_LIST_SIZE 877

int xedInit(void) {
   xed_tables_init();
   return 0;
}

void fixMmxRegs(char* buf, int bufLen) {

    // We are looking for the 'x' in 'mmx', so the string must be at least 3
    // letters, and we can skip the first two.
    if (*buf == '\0' || *(buf + 1) == '\0') {
        return;
    }
    
    char* cur = buf + 2;
    char* place = buf + 2;
    
    while (*cur) {
        if (*cur != 'x' || *(cur - 1) != 'm' || *(cur - 2) != 'm') {
            *place = *cur;
            place++;
        }
        cur++;
    }
    *place = '\0';
}

void fixVexMaskOperations(char* buf, int bufLen) {
    
    // Start at the beginning of the buffer and go to the end.
    char* cur = buf;
    while (*cur) {
        cur++;
    }

    // If the last character isn't a bracket, we aren't interested in this
    // insn, so return.
    if (*(cur - 1) != '}') {
        return;
    }

    // We will need to increase the length of the instruction by two, so make
    // sure we have room for that.
    char* insnEnd = cur - 1;
    if (buf + bufLen <= insnEnd + 2) {
        std::cerr << "ERROR: Decoding buffer too short!\n";
        exit(-1);
    }

    // Go back until we identify an opening brace.
    while (cur >= buf && *cur != '{') {
        cur--;
    }

    // Vector operations all begin with 'r' or 's'. If this braced value
    // doesn't, return.
    if (*(cur + 1) != 'r' && *(cur + 1) != 's') {
        return;
    }

    // We now know that were dealing with a vector operation. Record its length
    // and allocate a buffer to hold it.
    int opLen = strlen(cur);
    char tmpBuf[opLen + 1];
    char* tmp = &tmpBuf[0];
    strcpy(tmp, cur);

    // Start at the beginning of the instruction and find the first space,
    // which is where we want to place the vector operation.
    cur = buf;
    while (*cur && *cur != ' ') {
        cur++;
    }

    // If we didn't find a space, return.
    if (*cur != ' ') {
        return;
    }
    
    // We want to copy this before the first %*mm# register. There may be a single operand
    // before that register, so copy over and see.
    if (*(cur + 3) != 'm' || *(cur + 4) != 'm') {
        ++cur;
        while (*cur && *cur != ' ') {
            ++cur;
        }
    }

    // Verify that we found another place for the mask, or return.
    if (*cur != ' ') {
        return;
    }

    // Record the position to copy the operation to.
    char* opPos = cur + 1;
    int copyOffset = opLen + 2;

    // Copy the instruction starting at the end.
    cur = insnEnd + 2; // include space for the ", "
    *(cur + 1) = 0;
    while (cur >= opPos + copyOffset) {
        *cur = *(cur - copyOffset);
        cur--;
    }

    // We've now copied all of the instruction leaving space for the operation
    // and ", ", so add those in.
    strncpy(opPos, tmp, opLen);
    *(opPos + opLen) = ',';
    *(opPos + opLen + 1) = ' ';
}

void fixVexTrailingX(char* buf, int bufLen) {
    char* cur = buf;
    
    while (*cur && !((cur == buf || *(cur - 1) == ' ') && 
            *cur == 'v' /*&& *(cur + 2) == 'p'*/)) {
        cur++;
    }

    if (!*cur) {
        return;
    }

    while (*cur && *cur != ' ') {
        cur++;
    }

    if (*(cur - 1) == 'x' || *(cur - 1) == 'z') {
        while (*cur) {
            *(cur - 1) = *cur;
            cur++;
        }
        *(cur - 1) = '\0';
    }
}

static FindList* initFixPSRInsnSuffixFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, "psrldq ", "psrld ");
    Normalization::addReplaceTerm(*fl, "pslldq ", "pslld ");
    return fl;
}

static void fixPSRInsnSuffix(char* buf, int bufLen) {
    static FindList* fl = initFixPSRInsnSuffixFindList();
    if (strstr(buf, " %mm") != NULL) {
        fl->process(buf, bufLen);
    }
}

void fixPFInsnSuffix(char* buf, int bufLen) {
    char* cur = buf;
    bool done = false;
    while (!done && *cur) {
        if (!strncmp(cur, "pf", 2)) {
            done = true;
            while (*cur && *cur != ' ') {
                ++cur;
            }
            *(cur - 1) = ' ';
        }
        while (*cur && !isspace(*cur)) {
            ++cur;
        }
        if (*cur) {
            ++cur;
        }
    }
}

void fixPrefetchSuffix(char* buf, int bufLen) {
    char* cur = buf;
    bool done = false;
    while (!done && *cur) {
        if (!strncmp(cur, "prefetch", 8)) {
            done = true;
            cur += 8;
            while (*cur && *cur != ' ') {
                *cur = ' ';
                ++cur;
            }
        }
        while (*cur && !isspace(*cur)) {
            ++cur;
        }
        if (*cur) {
            ++cur;
        }
    }
}

FindList* initMaskNameFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, "rne-sae", "rn-sae");
    return fl;
}

void fixMaskName(char* buf, int bufLen) {
    static FindList* fl = initMaskNameFindList();
    fl->process(buf, bufLen);
}

FindList* initConvertFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, "ssq ", "ss ");
    Normalization::addReplaceTerm(*fl, "ssl ", "ss ");
    Normalization::addReplaceTerm(*fl, "sdl ", "sd ");
    Normalization::addReplaceTerm(*fl, "siq ", "si ");
    Normalization::addReplaceTerm(*fl, "pdq ", "pd ");
    Normalization::addReplaceTerm(*fl, "psq ", "ps ");
    Normalization::addReplaceTerm(*fl, "piq ", "pi ");
    Normalization::addReplaceTerm(*fl, "psl ", "ps ");
    Normalization::addReplaceTerm(*fl, "psq ", "ps ");
    Normalization::addReplaceTerm(*fl, "phq ", "ph ");
    Normalization::addReplaceTerm(*fl, "psx ", "ps ");
    Normalization::addReplaceTerm(*fl, "pix ", "pi ");
    Normalization::addReplaceTerm(*fl, "dqx ", "dq ");
    Normalization::addReplaceTerm(*fl, "wdy ", "wd ");
    return fl;
}

FindList* initNonConvertFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, "y ", " ");
    Normalization::addReplaceTerm(*fl, "x ", " ");
    return fl;
}

FindList* initVecFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    /* Removes all instructions that fall under "no such instruction" */
    Normalization::addReplaceTerm(*fl, "bx ", "b ");
    Normalization::addReplaceTerm(*fl, "by ", "b ");
    Normalization::addReplaceTerm(*fl, "wx ", "w ");
    Normalization::addReplaceTerm(*fl, "wy ", "w ");
    Normalization::addReplaceTerm(*fl, "dx ", "d ");
    Normalization::addReplaceTerm(*fl, "dy ", "d ");
    Normalization::addReplaceTerm(*fl, "px ", "p ");
    Normalization::addReplaceTerm(*fl, "py ", "p ");
    Normalization::addReplaceTerm(*fl, "qx ", "q ");
    Normalization::addReplaceTerm(*fl, "qy ", "q ");
    Normalization::addReplaceTerm(*fl, "rx ", "r ");
    Normalization::addReplaceTerm(*fl, "ry ", "r ");
    Normalization::addReplaceTerm(*fl, "nx ", "n ");
    Normalization::addReplaceTerm(*fl, "ny ", "n ");
    Normalization::addReplaceTerm(*fl, "sx ", "s ");
    Normalization::addReplaceTerm(*fl, "sy ", "s ");
    Normalization::addReplaceTerm(*fl, "2x ", "2 ");
    Normalization::addReplaceTerm(*fl, "2y ", "2 ");
    Normalization::addReplaceTerm(*fl, "4x ", "4 ");
    Normalization::addReplaceTerm(*fl, "4y ", "4 ");
    Normalization::addReplaceTerm(*fl, "8x ", "8 ");
    Normalization::addReplaceTerm(*fl, "8y ", "8 ");

    /* Remove unnecessary prefix letters from these instructions */
    Normalization::addRemoveLastLetterTerm(*fl, "vcvtps2phq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmclearq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmptrldq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmptrstq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpadddl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpanddl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpandndl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpblendmdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpbroadcastbb");
    Normalization::addRemoveLastLetterTerm(*fl, "vpbroadcastdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpeqdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpgtdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpudl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermi2dl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermi2psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermilpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermt2dl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermt2psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpinsrbb");
    Normalization::addRemoveLastLetterTerm(*fl, "vpinsrdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmaxsdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmaxudl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpminsdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpminudl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmovsxbdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmovsxbqw");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmovzxbdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmovzxbqw");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmulldl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpordl");
    Normalization::addRemoveLastLetterTerm(*fl, "vproldl");
    Normalization::addRemoveLastLetterTerm(*fl, "vprolvdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vprordl");
    Normalization::addRemoveLastLetterTerm(*fl, "vprorvdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpslldl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsllvdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsradl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsravdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsrldl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsrlvdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsubdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpternlogdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vptestmdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vptestnmdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpxordl");
    Normalization::addRemoveLastLetterTerm(*fl, "vaddpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vaddpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vaddsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vaddssl");
    Normalization::addRemoveLastLetterTerm(*fl, "valigndl");
    Normalization::addRemoveLastLetterTerm(*fl, "valignqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vandnpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vandnpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vandpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vandpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vblendmpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vcmpsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vcmpssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vcvtsd2ssq");
    Normalization::addRemoveLastLetterTerm(*fl, "vcvtss2sdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vdivpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vdivpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vdivsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vdivssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vextractpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfixupimmpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfixupimmpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfixupimmsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfixupimmssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd132pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd132psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd132sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd132ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd213pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd213psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd213sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd213ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd231pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd231psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd231sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmadd231ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsub132pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsub132psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsub213pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsub213psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsub231pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmaddsub231psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub132pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub132psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub132sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub132ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub213pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub213psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub213sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub213ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub231pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub231psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub231sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsub231ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubadd132pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubadd132psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubadd213psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubadd231pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubadd231psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd132pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd132psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd132sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd132ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd213pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd213psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd213sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd213ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd231pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd231psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd231sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmadd231ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmaddsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmaddssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub132pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub132psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub132sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub132ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub213pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub213psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub213sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub213ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub231pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub231psl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub231sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsub231ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsubsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfnmsubssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vgatherqpsq");
    Normalization::addRemoveLastLetterTerm(*fl, "vgetmantsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vgetmantssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vinsertpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmaxpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmaxpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmaxsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmaxssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vminpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vminpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vminsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vminssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovddupq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovhpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovhpsq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovlpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovlpsq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmulpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmulpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmulsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmulssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmxonq");
    Normalization::addRemoveLastLetterTerm(*fl, "vorpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vorpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpackssdwl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpackusdwl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpaddqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpandnqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpandqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpands");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpeqqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpgtqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpcmpuqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermi2pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermi2qq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermilpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermt2pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpermt2qq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpextrbb");
    Normalization::addRemoveLastLetterTerm(*fl, "vpextrdl");
    Normalization::addRemoveLastLetterTerm(*fl, "vpextrww");
    Normalization::addRemoveLastLetterTerm(*fl, "vpgatherqdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpinsrqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpinsrww");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmadd52luqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmaxsqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmaxuqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpminsqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpminuqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmuldqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmultishiftqbq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmuludqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vporqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vprolqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vprolvqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vprorqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vprorvqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsraqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsubqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpternlogqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpunpckhdql");
    Normalization::addRemoveLastLetterTerm(*fl, "vpunpckhqdqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpunpckldql");
    Normalization::addRemoveLastLetterTerm(*fl, "vpunpcklqdqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpxorqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovdqay");
    Normalization::addRemoveLastLetterTerm(*fl, "vrangepdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrangepsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrangesdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrangessl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrcp14sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrcp28sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrcp28ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrcpssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vreducesdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vreducessl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrndscalesdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrndscalessl");
    Normalization::addRemoveLastLetterTerm(*fl, "vroundsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vroundssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrsqrt28sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrsqrt28ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrsqrtssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vscalefpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vscalefpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vscalefsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vscalefssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vshuff32x4l");
    Normalization::addRemoveLastLetterTerm(*fl, "vshuff64x2q");
    Normalization::addRemoveLastLetterTerm(*fl, "vshufi64x2q");
    Normalization::addRemoveLastLetterTerm(*fl, "vsqrtsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vsqrtssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vsubpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vsubpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vsubsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vsubssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vunpckhpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vunpcklpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vxorpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vxorpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vblendmpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vcmppdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vcomisdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vcomissl");
    Normalization::addRemoveLastLetterTerm(*fl, "vcvtdq2pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vcvtps2pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vfmsubadd213pdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vgetexpsdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vgetexpssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vldmxcsrl");
    Normalization::addRemoveLastLetterTerm(*fl, "vmovqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpblendmqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmadd52huqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpmullqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsllqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsllvqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsravqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsrlqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vpsrlvqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vptestmqq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrcp14ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vrsqrt14sdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vrsqrt14ssl");
    Normalization::addRemoveLastLetterTerm(*fl, "vshufi32x4l");
    Normalization::addRemoveLastLetterTerm(*fl, "vshufpdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vstmxcsrl");
    Normalization::addRemoveLastLetterTerm(*fl, "vucomisdq");
    Normalization::addRemoveLastLetterTerm(*fl, "vucomissl");
    Normalization::addRemoveLastLetterTerm(*fl, "vunpckhpsl");
    Normalization::addRemoveLastLetterTerm(*fl, "vunpcklpsl");
    return fl;
}

FindList* initPInsnSuffixFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);

    /* Removes all instructions that fall under "no such instruction" */
    Normalization::addReplaceTerm(*fl, "rx ", "r ");
    Normalization::addReplaceTerm(*fl, "nx ", "n ");
    Normalization::addReplaceTerm(*fl, "bx ", "b ");
    Normalization::addReplaceTerm(*fl, "by ", "b ");
    Normalization::addReplaceTerm(*fl, "wx ", "w ");
    Normalization::addReplaceTerm(*fl, "wy ", "w ");
    Normalization::addReplaceTerm(*fl, "dx ", "d ");
    Normalization::addReplaceTerm(*fl, "dy ", "d ");
    Normalization::addReplaceTerm(*fl, "qx ", "q ");
    Normalization::addReplaceTerm(*fl, "qy ", "q ");
   
    /* Remove unnecessary prefixes from these instructions. */
    Normalization::addRemoveLastLetterTerm(*fl, "pushfqq");
    Normalization::addRemoveLastLetterTerm(*fl, "popfqq");
    Normalization::addRemoveLastLetterTerm(*fl, "pabsbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pabswx");
    Normalization::addRemoveLastLetterTerm(*fl, "packsswbx");
    Normalization::addRemoveLastLetterTerm(*fl, "packuswbx");
    Normalization::addRemoveLastLetterTerm(*fl, "paddbx");
    Normalization::addRemoveLastLetterTerm(*fl, "paddsbx");
    Normalization::addRemoveLastLetterTerm(*fl, "paddswx");
    Normalization::addRemoveLastLetterTerm(*fl, "paddusbx");
    Normalization::addRemoveLastLetterTerm(*fl, "padduswx");
    Normalization::addRemoveLastLetterTerm(*fl, "palignrx");
    Normalization::addRemoveLastLetterTerm(*fl, "pavgbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pavgwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pblendvbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpeqbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpeqwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpestrix");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpestrmx");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpgtbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpgtwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpistrix");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpistrmx");
    Normalization::addRemoveLastLetterTerm(*fl, "phaddswx");
    Normalization::addRemoveLastLetterTerm(*fl, "phminposuwx");
    Normalization::addRemoveLastLetterTerm(*fl, "phsubswx");
    Normalization::addRemoveLastLetterTerm(*fl, "phsubwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaddubswx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaxsbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaxswx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaxubx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaxuwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pminsbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pminswx");
    Normalization::addRemoveLastLetterTerm(*fl, "pminubx");
    Normalization::addRemoveLastLetterTerm(*fl, "pminuwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovsxb");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovsxw");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovzxw");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhrswx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhuwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pmullwx");
    Normalization::addRemoveLastLetterTerm(*fl, "psadbwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pshufbx");
    Normalization::addRemoveLastLetterTerm(*fl, "pshufhwx");
    Normalization::addRemoveLastLetterTerm(*fl, "pshuflwx");
    Normalization::addRemoveLastLetterTerm(*fl, "psignbx");
    Normalization::addRemoveLastLetterTerm(*fl, "psignwx");
    Normalization::addRemoveLastLetterTerm(*fl, "psllwx");
    Normalization::addRemoveLastLetterTerm(*fl, "psrawx");
    Normalization::addRemoveLastLetterTerm(*fl, "psrlwx");
    Normalization::addRemoveLastLetterTerm(*fl, "psubbx");
    Normalization::addRemoveLastLetterTerm(*fl, "psubsbx");
    Normalization::addRemoveLastLetterTerm(*fl, "psubswx");
    Normalization::addRemoveLastLetterTerm(*fl, "psubusbx");
    Normalization::addRemoveLastLetterTerm(*fl, "psubuswx");
    Normalization::addRemoveLastLetterTerm(*fl, "psubwx");
    Normalization::addRemoveLastLetterTerm(*fl, "ptestx");
    Normalization::addRemoveLastLetterTerm(*fl, "punpckhbwx");
    Normalization::addRemoveLastLetterTerm(*fl, "punpcklbwx");
    Normalization::addRemoveLastLetterTerm(*fl, "punpcklqd");
   
    Normalization::addRemoveLastLetterTerm(*fl, "pextrqq");
    Normalization::addRemoveLastLetterTerm(*fl, "pinsrqq");
    
    Normalization::addRemoveLastLetterTerm(*fl, "packssdwq");
    Normalization::addRemoveLastLetterTerm(*fl, "packsswbq");
    Normalization::addRemoveLastLetterTerm(*fl, "packuswbq");
    Normalization::addRemoveLastLetterTerm(*fl, "paddbq");
    Normalization::addRemoveLastLetterTerm(*fl, "padddq");
    Normalization::addRemoveLastLetterTerm(*fl, "paddqq");
    Normalization::addRemoveLastLetterTerm(*fl, "paddsbq");
    Normalization::addRemoveLastLetterTerm(*fl, "paddswq");
    Normalization::addRemoveLastLetterTerm(*fl, "paddusbq");
    Normalization::addRemoveLastLetterTerm(*fl, "padduswq");
    Normalization::addRemoveLastLetterTerm(*fl, "paddwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pandnq");
    Normalization::addRemoveLastLetterTerm(*fl, "pandq");
    Normalization::addRemoveLastLetterTerm(*fl, "pavgbq");
    Normalization::addRemoveLastLetterTerm(*fl, "pavgwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpeqbq");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpeqdq");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpeqwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpgtbq");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpgtdq");
    Normalization::addRemoveLastLetterTerm(*fl, "pcmpgtwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pinsrww");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaddwdq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaxswq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaxubq");
    Normalization::addRemoveLastLetterTerm(*fl, "pminswq");
    Normalization::addRemoveLastLetterTerm(*fl, "pminubq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhuwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmullwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmuludqq");
    Normalization::addRemoveLastLetterTerm(*fl, "porq");
    Normalization::addRemoveLastLetterTerm(*fl, "psadbwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pshufwq");
    Normalization::addRemoveLastLetterTerm(*fl, "psllqq");
    Normalization::addRemoveLastLetterTerm(*fl, "psllwq");
    Normalization::addRemoveLastLetterTerm(*fl, "psradq");
    Normalization::addRemoveLastLetterTerm(*fl, "psrawq");
    Normalization::addRemoveLastLetterTerm(*fl, "psrlqq");
    Normalization::addRemoveLastLetterTerm(*fl, "psrlwq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubbq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubdq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubqq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubsbq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubswq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubusbq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubuswq");
    Normalization::addRemoveLastLetterTerm(*fl, "psubwq");
    Normalization::addRemoveLastLetterTerm(*fl, "punpckhbwq");
    Normalization::addRemoveLastLetterTerm(*fl, "punpckhdqq");
    Normalization::addRemoveLastLetterTerm(*fl, "punpckhwdq");
    Normalization::addRemoveLastLetterTerm(*fl, "punpcklbwl");
    Normalization::addRemoveLastLetterTerm(*fl, "punpckldql");
    Normalization::addRemoveLastLetterTerm(*fl, "punpcklwdl");
    Normalization::addRemoveLastLetterTerm(*fl, "pxorq");
    Normalization::addRemoveLastLetterTerm(*fl, "pabsb");
    Normalization::addRemoveLastLetterTerm(*fl, "pabsd");
    Normalization::addRemoveLastLetterTerm(*fl, "pabsw");
    Normalization::addRemoveLastLetterTerm(*fl, "pavgusb");
    Normalization::addRemoveLastLetterTerm(*fl, "phaddd");
    Normalization::addRemoveLastLetterTerm(*fl, "phsubd");
    Normalization::addRemoveLastLetterTerm(*fl, "phsubw");
    Normalization::addRemoveLastLetterTerm(*fl, "pmaddubsw");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhrsw");
    Normalization::addRemoveLastLetterTerm(*fl, "pmulhrw");
    Normalization::addRemoveLastLetterTerm(*fl, "pshufb");
    Normalization::addRemoveLastLetterTerm(*fl, "psignb");
    Normalization::addRemoveLastLetterTerm(*fl, "psignd");
    Normalization::addRemoveLastLetterTerm(*fl, "psignw");
    Normalization::addRemoveLastLetterTerm(*fl, "palignrq");
    Normalization::addRemoveLastLetterTerm(*fl, "pandq");
    Normalization::addRemoveLastLetterTerm(*fl, "pextrbb");
    Normalization::addRemoveLastLetterTerm(*fl, "pextrdl");
    Normalization::addRemoveLastLetterTerm(*fl, "pinsrbb");
    Normalization::addRemoveLastLetterTerm(*fl, "pinsrdl");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovsxbdl");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovsxbqw");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovzxbdl");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovzxbqw");
    
    Normalization::addRemoveLastLetterTerm(*fl, "pextrww");
    Normalization::addRemoveLastLetterTerm(*fl, "phaddswq");
    Normalization::addRemoveLastLetterTerm(*fl, "phaddwq");
    Normalization::addRemoveLastLetterTerm(*fl, "phsubswq");
    Normalization::addRemoveLastLetterTerm(*fl, "pi2fdq");
    Normalization::addRemoveLastLetterTerm(*fl, "pi2fwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovsxdqq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovzxbwq");
    Normalization::addRemoveLastLetterTerm(*fl, "pmovzxdqq");
    Normalization::addRemoveLastLetterTerm(*fl, "pswapdq");
    
    return fl;
}

FindList* initRemoveLastLetterFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addRemoveLastLetterTerm(*fl, "cflush");
    Normalization::addRemoveLastLetterTerm(*fl, "clflush");
    Normalization::addRemoveLastLetterTerm(*fl, "vmclear");
    Normalization::addRemoveLastLetterTerm(*fl, "kmovbb");
    return fl;
}

FindList* initStrInsnDressingFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, "stosqq", "stosq");
    Normalization::addReplaceTerm(*fl, "movsqq", "movsq");
    Normalization::addReplaceTerm(*fl, "scasqq", "scasq");
    Normalization::addReplaceTerm(*fl, "insqq", "insq");
    Normalization::addReplaceTerm(*fl, "outsqq", "outsq");
    Normalization::addReplaceTerm(*fl, "lodsqq", "lodsq");
    Normalization::addReplaceTerm(*fl, "cmpsqq", "cmpsq");
    Normalization::addReplaceTerm(*fl, "stosll", "stosl");
    Normalization::addReplaceTerm(*fl, "movsll", "movsl");
    Normalization::addReplaceTerm(*fl, "scasll", "scasl");
    Normalization::addReplaceTerm(*fl, "insll", "insl");
    Normalization::addReplaceTerm(*fl, "outsll", "outsl");
    Normalization::addReplaceTerm(*fl, "lodsll", "lodsl");
    Normalization::addReplaceTerm(*fl, "cmpsll", "cmpsl");
    return fl;
}

FindList* initOpcodeDressingFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, "lslw ", "lsl ");
    Normalization::addReplaceTerm(*fl, "larw ", "lar ");
    Normalization::addReplaceTerm(*fl, "lgsw ", "lgs ");
    Normalization::addReplaceTerm(*fl, "lfsw ", "lfs ");
    Normalization::addReplaceTerm(*fl, "upq ", "up ");
    Normalization::addReplaceTerm(*fl, "bx ", "b ");
    Normalization::addReplaceTerm(*fl, "wx ", "w ");
    Normalization::addReplaceTerm(*fl, "dx ", "d ");
    Normalization::addReplaceTerm(*fl, "qx ", "q ");
    Normalization::addReplaceTerm(*fl, "by ", "b ");
    Normalization::addReplaceTerm(*fl, "bz ", "b ");
    Normalization::addReplaceTerm(*fl, "wl ", "w ");
    Normalization::addReplaceTerm(*fl, "wq ", "w ");
    Normalization::addReplaceTerm(*fl, "wy ", "w ");
    Normalization::addReplaceTerm(*fl, "wz ", "w ");
    Normalization::addReplaceTerm(*fl, "ww ", "w ");
    Normalization::addReplaceTerm(*fl, "sdl ", "sd ");
    Normalization::addReplaceTerm(*fl, "dy ", "d ");
    Normalization::addReplaceTerm(*fl, "dz ", "d ");
    Normalization::addReplaceTerm(*fl, "qql ", "qq ");
    Normalization::addReplaceTerm(*fl, "pdq ", "pd ");
    Normalization::addReplaceTerm(*fl, "sdq ", "sd ");
    Normalization::addReplaceTerm(*fl, "sbq ", "sb ");
    Normalization::addReplaceTerm(*fl, "dbq ", "db ");
    Normalization::addReplaceTerm(*fl, "wdq ", "wd ");
    Normalization::addReplaceTerm(*fl, "qz ", "q ");
    Normalization::addReplaceTerm(*fl, "rdl ", "rd ");
    Normalization::addReplaceTerm(*fl, "ldl ", "ld ");
    Normalization::addReplaceTerm(*fl, "dql ", "dq ");
    Normalization::addReplaceTerm(*fl, "wdl ", "wd ");
    Normalization::addReplaceTerm(*fl, "sdl ", "sl ");
    Normalization::addReplaceTerm(*fl, "fdl ", "fd ");
    Normalization::addReplaceTerm(*fl, "pdl ", "pd ");
    Normalization::addReplaceTerm(*fl, "bdl ", "bd ");
    Normalization::addReplaceTerm(*fl, "wql ", "wq ");
    Normalization::addReplaceTerm(*fl, "siq ", "si ");
    Normalization::addReplaceTerm(*fl, "sil ", "si ");
    Normalization::addReplaceTerm(*fl, "piq ", "pi ");
    Normalization::addReplaceTerm(*fl, "psq ", "ps ");
    Normalization::addReplaceTerm(*fl, "psx ", "ps ");
    Normalization::addReplaceTerm(*fl, "psy ", "ps ");
    Normalization::addReplaceTerm(*fl, "psl ", "ps ");
    Normalization::addReplaceTerm(*fl, "pdz ", "pd ");
    Normalization::addReplaceTerm(*fl, "nrq ", "nr ");
    Normalization::addReplaceTerm(*fl, "bqw ", "bq ");
    Normalization::addReplaceTerm(*fl, "nqq ", "nq ");
    Normalization::addReplaceTerm(*fl, "sww", "sw");
    Normalization::addReplaceTerm(*fl, "ssl", "ss");
    Normalization::addReplaceTerm(*fl, "x2q ", "x2 ");
    Normalization::addReplaceTerm(*fl, "x4q ", "x4 ");
    Normalization::addReplaceTerm(*fl, "x2l ", "x2 ");
    Normalization::addReplaceTerm(*fl, "x4l ", "x4 ");
    Normalization::addReplaceTerm(*fl, "movqq ", "movq ");
    Normalization::addReplaceTerm(*fl, "movntqq ", "movntq ");
    Normalization::addReplaceTerm(*fl, "pcmpgtbq", "pcmpgtb");
    Normalization::addReplaceTerm(*fl, "stmxcsrl", "stmxcsr");
    Normalization::addReplaceTerm(*fl, "ldmxcsrl", "ldmxcsr");
    Normalization::addReplaceTerm(*fl, "pextrbb", "pextrb");
    Normalization::addReplaceTerm(*fl, "sxd ", "slq ");
    Normalization::addReplaceTerm(*fl, "stosd", "stosl");
    Normalization::addReplaceTerm(*fl, "stosdl", "stosl");
    Normalization::addReplaceTerm(*fl, "fld ", "fldt ");
    Normalization::addReplaceTerm(*fl, "movdl", "movd");
    Normalization::addReplaceTerm(*fl, "iretd", "iretl");
    Normalization::addReplaceTerm(*fl, "scasbb", "scasb");
    Normalization::addReplaceTerm(*fl, "stosbb", "stosb");
    Normalization::addReplaceTerm(*fl, "stosd", "stosl");
    Normalization::addReplaceTerm(*fl, "scasd", "scasl");
    Normalization::addReplaceTerm(*fl, "scasdl", "scasl");
    Normalization::addReplaceTerm(*fl, "movsbb", "movsb");
    Normalization::addReplaceTerm(*fl, "insbb", "insb");
    Normalization::addReplaceTerm(*fl, "insww", "insw");
    Normalization::addReplaceTerm(*fl, "outsww", "outsw");
    Normalization::addReplaceTerm(*fl, "insdl", "insl");
    Normalization::addReplaceTerm(*fl, "outsbb", "outsb");
    Normalization::addReplaceTerm(*fl, "outsdl", "outsl");
    Normalization::addReplaceTerm(*fl, "lodsd", "lodsl");
    Normalization::addReplaceTerm(*fl, "lodsdl", "lodsl");
    Normalization::addReplaceTerm(*fl, "lodsbb", "lodsb");
    Normalization::addReplaceTerm(*fl, "cmpsbb", "cmpsb");
    Normalization::addReplaceTerm(*fl, "popfqq", "popfq");
    Normalization::addReplaceTerm(*fl, "pushfqq", "pushfq");
    Normalization::addReplaceTerm(*fl, "invlpgb", "invlpg");
    Normalization::addReplaceTerm(*fl, "lcallq", "lcall");
    Normalization::addReplaceTerm(*fl, "maskmovqq", "maskmovq");
    Normalization::addReplaceTerm(*fl, "fyl2 %st(1), %st(0)", "fyl2x");
    return fl;
}

void fixExtraOpcodeDressing(char* buf, int bufLen) {
    static FindList* fl = initOpcodeDressingFindList();
    static FindList* strInsnFl = initStrInsnDressingFindList();
    static FindList* nonConvertFl = initNonConvertFindList();
    static FindList* cvtFl = initConvertFindList();
    static FindList* vecFl = initVecFindList();
    static FindList* pFl = initPInsnSuffixFindList();
    static FindList* rllFl = initRemoveLastLetterFindList();
    rllFl->process(buf, bufLen);
    
    std::string str(buf);

    if (*buf == 'p' || str.find(" p") != std::string::npos) {
        pFl->process(buf, bufLen);
    } else if (*buf == 'v' || str.find(" v") != std::string::npos) {
        vecFl->process(buf, bufLen);
    } else if (str.find("cvt") == std::string::npos) {
        fl->process(buf, bufLen);
        nonConvertFl->process(buf, bufLen);
        strInsnFl->process(buf, bufLen);
    } else {
        cvtFl->process(buf, bufLen);
    }
}

void removeExtraAddr32(char* buf, int bufLen) {
    std::string str = std::string(buf);
    
    if (str.find("addr32 j") == std::string::npos) {
        return;
    }
   
    removeOperand(str, "", "addr32");

    strncpy(buf, str.c_str(), bufLen);
    if (buf[str.length() - 1] == ' ') {
       buf[str.length() - 1] = 0;
    }
}

void removeExtraData16(char* buf, int bufLen) {
    std::string str = std::string(buf);
    
    if (str.find("data16") == std::string::npos) {
        return;
    }
   
    removeOperand(str, "pushfw", "data16");
    removeOperand(str, "popfw", "data16");
    removeOperand(str, "cbw", "data16");
    removeOperand(str, "cwd", "data16");
    removeOperand(str, "leavew", "data16");

    strncpy(buf, str.c_str(), bufLen);
    if (buf[str.length() - 1] == ' ') {
       buf[str.length() - 1] = 0;
    }
}

void fixFloatSuffixes(char* buf, int bufLen) {
    char* cur = buf;
    bool done = false;
    while (*cur && !done) {
        if ((cur == buf || isspace(*(cur - 1))) && *cur == 'f') {
            if (!strncmp(cur, "fldcw", 5) || 
                !strncmp(cur, "fadds", 5) || 
                !strncmp(cur, "fmul ", 5) || 
                !strncmp(cur, "fimul ", 6) || 
                !strncmp(cur, "fidivl", 6) || 
                !strncmp(cur, "fidivrl", 7) || 
                !strncmp(cur, "fimull", 6) || 
                !strncmp(cur, "fiaddl", 6) || 
                !strncmp(cur, "ficoml", 6) || 
                !strncmp(cur, "ficompl", 7) || 
                !strncmp(cur, "fisubrl", 7) || 
                !strncmp(cur, "fisubrl", 7) || 
                !strncmp(cur, "fnstcw", 6) || 
                !strncmp(cur, "fnstsw", 6)) {
                return;
            }
            done = true;
            while (*cur && !isspace(*cur)) {
                ++cur;
            }
            //if (*cur) {
                if (*(cur - 1) == 'w') {
                    *(cur - 1) = ' ';
                } else if (*(cur - 1) == 'l') {
                    *(cur - 1) = 's';
                } else if (*(cur - 1) == 'q') {
                    *(cur - 1) = 'l';
                }
            //}
        }
        ++cur;
    }
}

void addImplicitRegs(char* buf, int bufLen) {
    std::string str = std::string(buf);
    if (str.find("outs") != std::string::npos) {
        char* cur = buf;
        while (*cur) {
            ++cur;
        }
        if (*(cur - 1) == ':') {
            strncpy(cur, "(%rsi)", bufLen - (cur - buf));
        }
    }
}

static void removeImplicitOperands(char* buf, int bufLen) {
    if (!strncmp(buf, "encl", 4)) {
        *(buf + 5) = '\0';
    }
    if (!strncmp(buf, "invlpga", 7)) {
        *(buf + 8) = '\0';
    }
    if (!strncmp(buf, "vmrun", 5)) {
        *(buf + 6) = '\0';
    }
    if (!strncmp(buf, "vmload", 6)) {
        *(buf + 7) = '\0';
    }
}

FindList* initFormatSegRegsFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addReplaceTerm(*fl, " fs:", " %fs:");
    Normalization::addReplaceTerm(*fl, " gs:", " %gs:");
    Normalization::addReplaceTerm(*fl, " cs:", " %cs:");
    Normalization::addReplaceTerm(*fl, " es:", " %es:");
    Normalization::addReplaceTerm(*fl, " ss:", " %ss:");
    Normalization::addReplaceTerm(*fl, " ds:", " %ds:");
    return fl;
}

static void formatSegRegs(char* buf, int bufLen) {
    static FindList* fl = initFormatSegRegsFindList();
    fl->process(buf, bufLen);
}

FindList* initSwapXEDOperandOrderFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    Normalization::addOperandSwapTerm(*fl, "vrange", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vfix", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vreduce", 1, 2);
    Normalization::addOperandSwapTerm(*fl, "vcmp", 1, 2);
    return fl;
}

void swapXEDOperandOrder(char* buf, int bufLen) {
    static FindList* fl = initSwapXEDOperandOrderFindList();
    fl->process(buf, bufLen);
}

void removeLockColon(char* buf, int bufLen) {
    std::string str = std::string(buf);
    auto index = str.find("lock :");
    if (index != std::string::npos) {
        buf[index + 5] = ' ';
    }
}

void xed_x86_64_norm(char* buf, int bufLen) {
    fixMmxRegs(buf, bufLen);
    fixExtraOpcodeDressing(buf, bufLen);
    fixVexTrailingX(buf, bufLen);
    fixVexMaskOperations(buf, bufLen);
    removeImplicitOperands(buf, bufLen);
    removeExtraData16(buf, bufLen);
    removeExtraAddr32(buf, bufLen);
    fixFloatSuffixes(buf, bufLen);
    removeLockColon(buf, bufLen);
    fixPrefetchSuffix(buf, bufLen);
    fixPFInsnSuffix(buf, bufLen);
    fixPSRInsnSuffix(buf, bufLen);
    addImplicitRegs(buf, bufLen);
    formatSegRegs(buf, bufLen);
}

int xed_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH;

    xed_error_enum_t err;
    xed_decoded_inst_t decoded_inst;

    xed_decoded_inst_zero(&decoded_inst);
    xed_decoded_inst_set_mode(&decoded_inst, mmode, stack_addr_width);
    err = xed_decode(&decoded_inst, (xed_uint8_t*)inst, nBytes);
    if (err != XED_ERROR_NONE) {
        return -1;
    }
    if (!xed_format_context(XED_SYNTAX_ATT, 
            &decoded_inst, buf, bufLen, 0, 0, 0)) {
        return -1;
    }
    return 0;
}

static void removeImplicitEnclOperands(char* buf, int bufLen) {
    if (!strncmp(buf, "encl", 4)) {
        *(buf + 5) = '\0';
    }
}

void xed_x86_32_norm(char* buf, int bufLen) {
    fixMmxRegs(buf, bufLen);
    fixExtraOpcodeDressing(buf, bufLen);
    fixVexTrailingX(buf, bufLen);
    fixVexMaskOperations(buf, bufLen);
    removeImplicitEnclOperands(buf, bufLen);
    removeExtraData16(buf, bufLen);
    removeExtraAddr32(buf, bufLen);
    fixFloatSuffixes(buf, bufLen);
    removeLockColon(buf, bufLen);
    fixPrefetchSuffix(buf, bufLen);
    fixPFInsnSuffix(buf, bufLen);
    addImplicitRegs(buf, bufLen);
}

int xed_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LEGACY_32;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_32b;

    xed_error_enum_t err;
    xed_decoded_inst_t decoded_inst;

    xed_decoded_inst_zero(&decoded_inst);
    xed_decoded_inst_set_mode(&decoded_inst, mmode, stack_addr_width);
    err = xed_decode(&decoded_inst, (xed_uint8_t*)inst, nBytes);
    if (err != XED_ERROR_NONE) {
        return -1;
    }
    if (!xed_format_context(XED_SYNTAX_ATT, 
            &decoded_inst, buf, bufLen, 0, 0, 0)) {
        return -1;
    }
    return 0;
}

Decoder* dec_xed_x86_32 = new Decoder(&xed_x86_32_decode, &xedInit, 
            &xed_x86_32_norm, "xed", "x86_32");
Decoder* dec_xed_x86_64 = new Decoder(&xed_x86_64_decode, &xedInit, 
            &xed_x86_64_norm, "xed", "x86_64");

