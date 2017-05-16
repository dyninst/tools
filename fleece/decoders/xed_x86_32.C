
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
#include "Normalization.h"
#include "StringUtils.h"

#define XED_MACHINE_MODE XED_MACHINE_MODE_LEGACY_32
#define XED_ADDRESS_WIDTH XED_ADDRESS_WIDTH_32b

#define FIND_LIST_SIZE 877

static int xedInit(void) {
   xed_tables_init();
   return 0;
}

static void fixMmxRegs(char* buf, int bufLen) {

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

static void fixVexMaskOperations(char* buf, int bufLen) {
    
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

static void fixVexTrailingX(char* buf, int bufLen) {
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

static void fixPFInsnSuffix(char* buf, int bufLen) {
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

static void fixPrefetchSuffix(char* buf, int bufLen) {
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

static FindList* initMaskNameFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addReplaceTerm(*fl, "rne-sae", "rn-sae");
    return fl;
}

static void fixMaskName(char* buf, int bufLen) {
    static FindList* fl = initMaskNameFindList();
    fl->process(buf, bufLen);
}

static FindList* initConvertFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addReplaceTerm(*fl, "ssq ", "ss ");
    addReplaceTerm(*fl, "ssl ", "ss ");
    addReplaceTerm(*fl, "sdl ", "sd ");
    addReplaceTerm(*fl, "siq ", "si ");
    addReplaceTerm(*fl, "pdq ", "pd ");
    addReplaceTerm(*fl, "psq ", "ps ");
    addReplaceTerm(*fl, "piq ", "pi ");
    addReplaceTerm(*fl, "psl ", "ps ");
    addReplaceTerm(*fl, "psq ", "ps ");
    addReplaceTerm(*fl, "phq ", "ph ");
    addReplaceTerm(*fl, "psx ", "ps ");
    addReplaceTerm(*fl, "pix ", "pi ");
    addReplaceTerm(*fl, "dqx ", "dq ");
    addReplaceTerm(*fl, "wdy ", "wd ");
    return fl;
}

static FindList* initNonConvertFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addReplaceTerm(*fl, "y ", " ");
    addReplaceTerm(*fl, "x ", " ");
    return fl;
}

static FindList* initVecFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    /* Removes all instructions that fall under "no such instruction" */
    addReplaceTerm(*fl, "bx ", "b ");
    addReplaceTerm(*fl, "by ", "b ");
    addReplaceTerm(*fl, "wx ", "w ");
    addReplaceTerm(*fl, "wy ", "w ");
    addReplaceTerm(*fl, "dx ", "d ");
    addReplaceTerm(*fl, "dy ", "d ");
    addReplaceTerm(*fl, "px ", "p ");
    addReplaceTerm(*fl, "py ", "p ");
    addReplaceTerm(*fl, "qx ", "q ");
    addReplaceTerm(*fl, "qy ", "q ");
    addReplaceTerm(*fl, "rx ", "r ");
    addReplaceTerm(*fl, "ry ", "r ");
    addReplaceTerm(*fl, "nx ", "n ");
    addReplaceTerm(*fl, "ny ", "n ");
    addReplaceTerm(*fl, "sx ", "s ");
    addReplaceTerm(*fl, "sy ", "s ");
    addReplaceTerm(*fl, "2x ", "2 ");
    addReplaceTerm(*fl, "2y ", "2 ");
    addReplaceTerm(*fl, "4x ", "4 ");
    addReplaceTerm(*fl, "4y ", "4 ");
    addReplaceTerm(*fl, "8x ", "8 ");
    addReplaceTerm(*fl, "8y ", "8 ");

    /* Remove unnecessary prefix letters from these instructions */
    addRemoveLastLetterTerm(*fl, "vcvtps2phq");
    addRemoveLastLetterTerm(*fl, "vmclearq");
    addRemoveLastLetterTerm(*fl, "vmptrldq");
    addRemoveLastLetterTerm(*fl, "vmptrstq");
    addRemoveLastLetterTerm(*fl, "vpadddl");
    addRemoveLastLetterTerm(*fl, "vpanddl");
    addRemoveLastLetterTerm(*fl, "vpandndl");
    addRemoveLastLetterTerm(*fl, "vpblendmdl");
    addRemoveLastLetterTerm(*fl, "vpbroadcastbb");
    addRemoveLastLetterTerm(*fl, "vpbroadcastdl");
    addRemoveLastLetterTerm(*fl, "vpcmpdl");
    addRemoveLastLetterTerm(*fl, "vpcmpeqdl");
    addRemoveLastLetterTerm(*fl, "vpcmpgtdl");
    addRemoveLastLetterTerm(*fl, "vpcmpudl");
    addRemoveLastLetterTerm(*fl, "vpermdl");
    addRemoveLastLetterTerm(*fl, "vpermi2dl");
    addRemoveLastLetterTerm(*fl, "vpermi2psl");
    addRemoveLastLetterTerm(*fl, "vpermilpsl");
    addRemoveLastLetterTerm(*fl, "vpermpsl");
    addRemoveLastLetterTerm(*fl, "vpermt2dl");
    addRemoveLastLetterTerm(*fl, "vpermt2psl");
    addRemoveLastLetterTerm(*fl, "vpinsrbb");
    addRemoveLastLetterTerm(*fl, "vpinsrdl");
    addRemoveLastLetterTerm(*fl, "vpmaxsdl");
    addRemoveLastLetterTerm(*fl, "vpmaxudl");
    addRemoveLastLetterTerm(*fl, "vpminsdl");
    addRemoveLastLetterTerm(*fl, "vpminudl");
    addRemoveLastLetterTerm(*fl, "vpmovsxbdl");
    addRemoveLastLetterTerm(*fl, "vpmovsxbqw");
    addRemoveLastLetterTerm(*fl, "vpmovzxbdl");
    addRemoveLastLetterTerm(*fl, "vpmovzxbqw");
    addRemoveLastLetterTerm(*fl, "vpmulldl");
    addRemoveLastLetterTerm(*fl, "vpordl");
    addRemoveLastLetterTerm(*fl, "vproldl");
    addRemoveLastLetterTerm(*fl, "vprolvdl");
    addRemoveLastLetterTerm(*fl, "vprordl");
    addRemoveLastLetterTerm(*fl, "vprorvdl");
    addRemoveLastLetterTerm(*fl, "vpslldl");
    addRemoveLastLetterTerm(*fl, "vpsllvdl");
    addRemoveLastLetterTerm(*fl, "vpsradl");
    addRemoveLastLetterTerm(*fl, "vpsravdl");
    addRemoveLastLetterTerm(*fl, "vpsrldl");
    addRemoveLastLetterTerm(*fl, "vpsrlvdl");
    addRemoveLastLetterTerm(*fl, "vpsubdl");
    addRemoveLastLetterTerm(*fl, "vpternlogdl");
    addRemoveLastLetterTerm(*fl, "vptestmdl");
    addRemoveLastLetterTerm(*fl, "vptestnmdl");
    addRemoveLastLetterTerm(*fl, "vpxordl");
    addRemoveLastLetterTerm(*fl, "vaddpdq");
    addRemoveLastLetterTerm(*fl, "vaddpsl");
    addRemoveLastLetterTerm(*fl, "vaddsdq");
    addRemoveLastLetterTerm(*fl, "vaddssl");
    addRemoveLastLetterTerm(*fl, "valigndl");
    addRemoveLastLetterTerm(*fl, "valignqq");
    addRemoveLastLetterTerm(*fl, "vandnpdq");
    addRemoveLastLetterTerm(*fl, "vandnpsl");
    addRemoveLastLetterTerm(*fl, "vandpdq");
    addRemoveLastLetterTerm(*fl, "vandpsl");
    addRemoveLastLetterTerm(*fl, "vblendmpsl");
    addRemoveLastLetterTerm(*fl, "vcmpsdq");
    addRemoveLastLetterTerm(*fl, "vcmpssl");
    addRemoveLastLetterTerm(*fl, "vcvtsd2ssq");
    addRemoveLastLetterTerm(*fl, "vcvtss2sdl");
    addRemoveLastLetterTerm(*fl, "vdivpdq");
    addRemoveLastLetterTerm(*fl, "vdivpsl");
    addRemoveLastLetterTerm(*fl, "vdivsdq");
    addRemoveLastLetterTerm(*fl, "vdivssl");
    addRemoveLastLetterTerm(*fl, "vextractpsl");
    addRemoveLastLetterTerm(*fl, "vfixupimmpdq");
    addRemoveLastLetterTerm(*fl, "vfixupimmpsl");
    addRemoveLastLetterTerm(*fl, "vfixupimmsdq");
    addRemoveLastLetterTerm(*fl, "vfixupimmssl");
    addRemoveLastLetterTerm(*fl, "vfmadd132pdq");
    addRemoveLastLetterTerm(*fl, "vfmadd132psl");
    addRemoveLastLetterTerm(*fl, "vfmadd132sdq");
    addRemoveLastLetterTerm(*fl, "vfmadd132ssl");
    addRemoveLastLetterTerm(*fl, "vfmadd213pdq");
    addRemoveLastLetterTerm(*fl, "vfmadd213psl");
    addRemoveLastLetterTerm(*fl, "vfmadd213sdq");
    addRemoveLastLetterTerm(*fl, "vfmadd213ssl");
    addRemoveLastLetterTerm(*fl, "vfmadd231pdq");
    addRemoveLastLetterTerm(*fl, "vfmadd231psl");
    addRemoveLastLetterTerm(*fl, "vfmadd231sdq");
    addRemoveLastLetterTerm(*fl, "vfmadd231ssl");
    addRemoveLastLetterTerm(*fl, "vfmaddsdq");
    addRemoveLastLetterTerm(*fl, "vfmaddssl");
    addRemoveLastLetterTerm(*fl, "vfmaddsub132pdq");
    addRemoveLastLetterTerm(*fl, "vfmaddsub132psl");
    addRemoveLastLetterTerm(*fl, "vfmaddsub213pdq");
    addRemoveLastLetterTerm(*fl, "vfmaddsub213psl");
    addRemoveLastLetterTerm(*fl, "vfmaddsub231pdq");
    addRemoveLastLetterTerm(*fl, "vfmaddsub231psl");
    addRemoveLastLetterTerm(*fl, "vfmsub132pdq");
    addRemoveLastLetterTerm(*fl, "vfmsub132psl");
    addRemoveLastLetterTerm(*fl, "vfmsub132sdq");
    addRemoveLastLetterTerm(*fl, "vfmsub132ssl");
    addRemoveLastLetterTerm(*fl, "vfmsub213pdq");
    addRemoveLastLetterTerm(*fl, "vfmsub213psl");
    addRemoveLastLetterTerm(*fl, "vfmsub213sdq");
    addRemoveLastLetterTerm(*fl, "vfmsub213ssl");
    addRemoveLastLetterTerm(*fl, "vfmsub231pdq");
    addRemoveLastLetterTerm(*fl, "vfmsub231psl");
    addRemoveLastLetterTerm(*fl, "vfmsub231sdq");
    addRemoveLastLetterTerm(*fl, "vfmsub231ssl");
    addRemoveLastLetterTerm(*fl, "vfmsubadd132pdq");
    addRemoveLastLetterTerm(*fl, "vfmsubadd132psl");
    addRemoveLastLetterTerm(*fl, "vfmsubadd213psl");
    addRemoveLastLetterTerm(*fl, "vfmsubadd231pdq");
    addRemoveLastLetterTerm(*fl, "vfmsubadd231psl");
    addRemoveLastLetterTerm(*fl, "vfmsubsdq");
    addRemoveLastLetterTerm(*fl, "vfmsubssl");
    addRemoveLastLetterTerm(*fl, "vfnmadd132pdq");
    addRemoveLastLetterTerm(*fl, "vfnmadd132psl");
    addRemoveLastLetterTerm(*fl, "vfnmadd132sdq");
    addRemoveLastLetterTerm(*fl, "vfnmadd132ssl");
    addRemoveLastLetterTerm(*fl, "vfnmadd213pdq");
    addRemoveLastLetterTerm(*fl, "vfnmadd213psl");
    addRemoveLastLetterTerm(*fl, "vfnmadd213sdq");
    addRemoveLastLetterTerm(*fl, "vfnmadd213ssl");
    addRemoveLastLetterTerm(*fl, "vfnmadd231pdq");
    addRemoveLastLetterTerm(*fl, "vfnmadd231psl");
    addRemoveLastLetterTerm(*fl, "vfnmadd231sdq");
    addRemoveLastLetterTerm(*fl, "vfnmadd231ssl");
    addRemoveLastLetterTerm(*fl, "vfnmaddsdq");
    addRemoveLastLetterTerm(*fl, "vfnmaddssl");
    addRemoveLastLetterTerm(*fl, "vfnmsub132pdq");
    addRemoveLastLetterTerm(*fl, "vfnmsub132psl");
    addRemoveLastLetterTerm(*fl, "vfnmsub132sdq");
    addRemoveLastLetterTerm(*fl, "vfnmsub132ssl");
    addRemoveLastLetterTerm(*fl, "vfnmsub213pdq");
    addRemoveLastLetterTerm(*fl, "vfnmsub213psl");
    addRemoveLastLetterTerm(*fl, "vfnmsub213sdq");
    addRemoveLastLetterTerm(*fl, "vfnmsub213ssl");
    addRemoveLastLetterTerm(*fl, "vfnmsub231pdq");
    addRemoveLastLetterTerm(*fl, "vfnmsub231psl");
    addRemoveLastLetterTerm(*fl, "vfnmsub231sdq");
    addRemoveLastLetterTerm(*fl, "vfnmsub231ssl");
    addRemoveLastLetterTerm(*fl, "vfnmsubsdq");
    addRemoveLastLetterTerm(*fl, "vfnmsubssl");
    addRemoveLastLetterTerm(*fl, "vgatherqpsq");
    addRemoveLastLetterTerm(*fl, "vgetmantsdq");
    addRemoveLastLetterTerm(*fl, "vgetmantssl");
    addRemoveLastLetterTerm(*fl, "vinsertpsl");
    addRemoveLastLetterTerm(*fl, "vmaxpdq");
    addRemoveLastLetterTerm(*fl, "vmaxpsl");
    addRemoveLastLetterTerm(*fl, "vmaxsdq");
    addRemoveLastLetterTerm(*fl, "vmaxssl");
    addRemoveLastLetterTerm(*fl, "vminpdq");
    addRemoveLastLetterTerm(*fl, "vminpsl");
    addRemoveLastLetterTerm(*fl, "vminsdq");
    addRemoveLastLetterTerm(*fl, "vminssl");
    addRemoveLastLetterTerm(*fl, "vmovddupq");
    addRemoveLastLetterTerm(*fl, "vmovdl");
    addRemoveLastLetterTerm(*fl, "vmovhpdq");
    addRemoveLastLetterTerm(*fl, "vmovhpsq");
    addRemoveLastLetterTerm(*fl, "vmovlpdq");
    addRemoveLastLetterTerm(*fl, "vmovlpsq");
    addRemoveLastLetterTerm(*fl, "vmovsdq");
    addRemoveLastLetterTerm(*fl, "vmovssl");
    addRemoveLastLetterTerm(*fl, "vmulpdq");
    addRemoveLastLetterTerm(*fl, "vmulpsl");
    addRemoveLastLetterTerm(*fl, "vmulsdq");
    addRemoveLastLetterTerm(*fl, "vmulssl");
    addRemoveLastLetterTerm(*fl, "vmxonq");
    addRemoveLastLetterTerm(*fl, "vorpdq");
    addRemoveLastLetterTerm(*fl, "vorpsl");
    addRemoveLastLetterTerm(*fl, "vpackssdwl");
    addRemoveLastLetterTerm(*fl, "vpackusdwl");
    addRemoveLastLetterTerm(*fl, "vpaddqq");
    addRemoveLastLetterTerm(*fl, "vpandnqq");
    addRemoveLastLetterTerm(*fl, "vpandqq");
    addRemoveLastLetterTerm(*fl, "vpands");
    addRemoveLastLetterTerm(*fl, "vpcmpeqqq");
    addRemoveLastLetterTerm(*fl, "vpcmpgtqq");
    addRemoveLastLetterTerm(*fl, "vpcmpqq");
    addRemoveLastLetterTerm(*fl, "vpcmpuqq");
    addRemoveLastLetterTerm(*fl, "vpermi2pdq");
    addRemoveLastLetterTerm(*fl, "vpermi2qq");
    addRemoveLastLetterTerm(*fl, "vpermilpdq");
    addRemoveLastLetterTerm(*fl, "vpermpdq");
    addRemoveLastLetterTerm(*fl, "vpermqq");
    addRemoveLastLetterTerm(*fl, "vpermt2pdq");
    addRemoveLastLetterTerm(*fl, "vpermt2qq");
    addRemoveLastLetterTerm(*fl, "vpextrbb");
    addRemoveLastLetterTerm(*fl, "vpextrdl");
    addRemoveLastLetterTerm(*fl, "vpextrww");
    addRemoveLastLetterTerm(*fl, "vpgatherqdq");
    addRemoveLastLetterTerm(*fl, "vpinsrqq");
    addRemoveLastLetterTerm(*fl, "vpinsrww");
    addRemoveLastLetterTerm(*fl, "vpmadd52luqq");
    addRemoveLastLetterTerm(*fl, "vpmaxsqq");
    addRemoveLastLetterTerm(*fl, "vpmaxuqq");
    addRemoveLastLetterTerm(*fl, "vpminsqq");
    addRemoveLastLetterTerm(*fl, "vpminuqq");
    addRemoveLastLetterTerm(*fl, "vpmuldqq");
    addRemoveLastLetterTerm(*fl, "vpmultishiftqbq");
    addRemoveLastLetterTerm(*fl, "vpmuludqq");
    addRemoveLastLetterTerm(*fl, "vporqq");
    addRemoveLastLetterTerm(*fl, "vprolqq");
    addRemoveLastLetterTerm(*fl, "vprolvqq");
    addRemoveLastLetterTerm(*fl, "vprorqq");
    addRemoveLastLetterTerm(*fl, "vprorvqq");
    addRemoveLastLetterTerm(*fl, "vpsraqq");
    addRemoveLastLetterTerm(*fl, "vpsubqq");
    addRemoveLastLetterTerm(*fl, "vpternlogqq");
    addRemoveLastLetterTerm(*fl, "vpunpckhdql");
    addRemoveLastLetterTerm(*fl, "vpunpckhqdqq");
    addRemoveLastLetterTerm(*fl, "vpunpckldql");
    addRemoveLastLetterTerm(*fl, "vpunpcklqdqq");
    addRemoveLastLetterTerm(*fl, "vpxorqq");
    addRemoveLastLetterTerm(*fl, "vrangepdq");
    addRemoveLastLetterTerm(*fl, "vrangepsl");
    addRemoveLastLetterTerm(*fl, "vrangesdq");
    addRemoveLastLetterTerm(*fl, "vrangessl");
    addRemoveLastLetterTerm(*fl, "vrcp14sdq");
    addRemoveLastLetterTerm(*fl, "vrcp28sdq");
    addRemoveLastLetterTerm(*fl, "vrcp28ssl");
    addRemoveLastLetterTerm(*fl, "vrcpssl");
    addRemoveLastLetterTerm(*fl, "vreducesdq");
    addRemoveLastLetterTerm(*fl, "vreducessl");
    addRemoveLastLetterTerm(*fl, "vrndscalesdq");
    addRemoveLastLetterTerm(*fl, "vrndscalessl");
    addRemoveLastLetterTerm(*fl, "vroundsdq");
    addRemoveLastLetterTerm(*fl, "vroundssl");
    addRemoveLastLetterTerm(*fl, "vrsqrt28sdq");
    addRemoveLastLetterTerm(*fl, "vrsqrt28ssl");
    addRemoveLastLetterTerm(*fl, "vrsqrtssl");
    addRemoveLastLetterTerm(*fl, "vscalefpdq");
    addRemoveLastLetterTerm(*fl, "vscalefpsl");
    addRemoveLastLetterTerm(*fl, "vscalefsdq");
    addRemoveLastLetterTerm(*fl, "vscalefssl");
    addRemoveLastLetterTerm(*fl, "vshuff32x4l");
    addRemoveLastLetterTerm(*fl, "vshuff64x2q");
    addRemoveLastLetterTerm(*fl, "vshufi64x2q");
    addRemoveLastLetterTerm(*fl, "vsqrtsdq");
    addRemoveLastLetterTerm(*fl, "vsqrtssl");
    addRemoveLastLetterTerm(*fl, "vsubpdq");
    addRemoveLastLetterTerm(*fl, "vsubpsl");
    addRemoveLastLetterTerm(*fl, "vsubsdq");
    addRemoveLastLetterTerm(*fl, "vsubssl");
    addRemoveLastLetterTerm(*fl, "vunpckhpdq");
    addRemoveLastLetterTerm(*fl, "vunpcklpdq");
    addRemoveLastLetterTerm(*fl, "vxorpdq");
    addRemoveLastLetterTerm(*fl, "vxorpsl");
    
    return fl;
}

static FindList* initPInsnSuffixFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);

    /* Removes all instructions that fall under "no such instruction" */
    addReplaceTerm(*fl, "rx ", "r ");
    addReplaceTerm(*fl, "nx ", "n ");
    addReplaceTerm(*fl, "bx ", "b ");
    addReplaceTerm(*fl, "by ", "b ");
    addReplaceTerm(*fl, "wx ", "w ");
    addReplaceTerm(*fl, "wy ", "w ");
    addReplaceTerm(*fl, "dx ", "d ");
    addReplaceTerm(*fl, "dy ", "d ");
    addReplaceTerm(*fl, "qx ", "q ");
    addReplaceTerm(*fl, "qy ", "q ");
   
    /* Remove unnecessary prefixes from these instructions. */
    addRemoveLastLetterTerm(*fl, "pushfqq");
    addRemoveLastLetterTerm(*fl, "popfqq");
    addRemoveLastLetterTerm(*fl, "pabsbx");
    addRemoveLastLetterTerm(*fl, "pabswx");
    addRemoveLastLetterTerm(*fl, "packsswbx");
    addRemoveLastLetterTerm(*fl, "packuswbx");
    addRemoveLastLetterTerm(*fl, "paddbx");
    addRemoveLastLetterTerm(*fl, "paddsbx");
    addRemoveLastLetterTerm(*fl, "paddswx");
    addRemoveLastLetterTerm(*fl, "paddusbx");
    addRemoveLastLetterTerm(*fl, "padduswx");
    addRemoveLastLetterTerm(*fl, "palignrx");
    addRemoveLastLetterTerm(*fl, "pavgbx");
    addRemoveLastLetterTerm(*fl, "pavgwx");
    addRemoveLastLetterTerm(*fl, "pblendvbx");
    addRemoveLastLetterTerm(*fl, "pcmpeqbx");
    addRemoveLastLetterTerm(*fl, "pcmpeqwx");
    addRemoveLastLetterTerm(*fl, "pcmpestrix");
    addRemoveLastLetterTerm(*fl, "pcmpestrmx");
    addRemoveLastLetterTerm(*fl, "pcmpgtbx");
    addRemoveLastLetterTerm(*fl, "pcmpgtwx");
    addRemoveLastLetterTerm(*fl, "pcmpistrix");
    addRemoveLastLetterTerm(*fl, "pcmpistrmx");
    addRemoveLastLetterTerm(*fl, "phaddswx");
    addRemoveLastLetterTerm(*fl, "phminposuwx");
    addRemoveLastLetterTerm(*fl, "phsubswx");
    addRemoveLastLetterTerm(*fl, "phsubwx");
    addRemoveLastLetterTerm(*fl, "pmaddubswx");
    addRemoveLastLetterTerm(*fl, "pmaxsbx");
    addRemoveLastLetterTerm(*fl, "pmaxswx");
    addRemoveLastLetterTerm(*fl, "pmaxubx");
    addRemoveLastLetterTerm(*fl, "pmaxuwx");
    addRemoveLastLetterTerm(*fl, "pminsbx");
    addRemoveLastLetterTerm(*fl, "pminswx");
    addRemoveLastLetterTerm(*fl, "pminubx");
    addRemoveLastLetterTerm(*fl, "pminuwx");
    addRemoveLastLetterTerm(*fl, "pmovsxb");
    addRemoveLastLetterTerm(*fl, "pmovsxw");
    addRemoveLastLetterTerm(*fl, "pmovzxw");
    addRemoveLastLetterTerm(*fl, "pmulhrswx");
    addRemoveLastLetterTerm(*fl, "pmulhuwx");
    addRemoveLastLetterTerm(*fl, "pmulhwx");
    addRemoveLastLetterTerm(*fl, "pmullwx");
    addRemoveLastLetterTerm(*fl, "psadbwx");
    addRemoveLastLetterTerm(*fl, "pshufbx");
    addRemoveLastLetterTerm(*fl, "pshufhwx");
    addRemoveLastLetterTerm(*fl, "pshuflwx");
    addRemoveLastLetterTerm(*fl, "psignbx");
    addRemoveLastLetterTerm(*fl, "psignwx");
    addRemoveLastLetterTerm(*fl, "psllwx");
    addRemoveLastLetterTerm(*fl, "psrawx");
    addRemoveLastLetterTerm(*fl, "psrlwx");
    addRemoveLastLetterTerm(*fl, "psubbx");
    addRemoveLastLetterTerm(*fl, "psubsbx");
    addRemoveLastLetterTerm(*fl, "psubswx");
    addRemoveLastLetterTerm(*fl, "psubusbx");
    addRemoveLastLetterTerm(*fl, "psubuswx");
    addRemoveLastLetterTerm(*fl, "psubwx");
    addRemoveLastLetterTerm(*fl, "ptestx");
    addRemoveLastLetterTerm(*fl, "punpckhbwx");
    addRemoveLastLetterTerm(*fl, "punpcklbwx");
    addRemoveLastLetterTerm(*fl, "punpcklqd");
    
    
    addRemoveLastLetterTerm(*fl, "packssdwq");
    addRemoveLastLetterTerm(*fl, "packsswbq");
    addRemoveLastLetterTerm(*fl, "packuswbq");
    addRemoveLastLetterTerm(*fl, "paddbq");
    addRemoveLastLetterTerm(*fl, "padddq");
    addRemoveLastLetterTerm(*fl, "paddqq");
    addRemoveLastLetterTerm(*fl, "paddsbq");
    addRemoveLastLetterTerm(*fl, "paddswq");
    addRemoveLastLetterTerm(*fl, "paddusbq");
    addRemoveLastLetterTerm(*fl, "padduswq");
    addRemoveLastLetterTerm(*fl, "paddwq");
    addRemoveLastLetterTerm(*fl, "pandnq");
    addRemoveLastLetterTerm(*fl, "pandq");
    addRemoveLastLetterTerm(*fl, "pavgbq");
    addRemoveLastLetterTerm(*fl, "pavgwq");
    addRemoveLastLetterTerm(*fl, "pcmpeqbq");
    addRemoveLastLetterTerm(*fl, "pcmpeqdq");
    addRemoveLastLetterTerm(*fl, "pcmpeqwq");
    addRemoveLastLetterTerm(*fl, "pcmpgtbq");
    addRemoveLastLetterTerm(*fl, "pcmpgtdq");
    addRemoveLastLetterTerm(*fl, "pcmpgtwq");
    addRemoveLastLetterTerm(*fl, "pinsrww");
    addRemoveLastLetterTerm(*fl, "pmaddwdq");
    addRemoveLastLetterTerm(*fl, "pmaxswq");
    addRemoveLastLetterTerm(*fl, "pmaxubq");
    addRemoveLastLetterTerm(*fl, "pminswq");
    addRemoveLastLetterTerm(*fl, "pminubq");
    addRemoveLastLetterTerm(*fl, "pmulhuwq");
    addRemoveLastLetterTerm(*fl, "pmulhwq");
    addRemoveLastLetterTerm(*fl, "pmullwq");
    addRemoveLastLetterTerm(*fl, "pmuludqq");
    addRemoveLastLetterTerm(*fl, "porq");
    addRemoveLastLetterTerm(*fl, "psadbwq");
    addRemoveLastLetterTerm(*fl, "pshufwq");
    addRemoveLastLetterTerm(*fl, "psllqq");
    addRemoveLastLetterTerm(*fl, "psllwq");
    addRemoveLastLetterTerm(*fl, "psradq");
    addRemoveLastLetterTerm(*fl, "psrawq");
    addRemoveLastLetterTerm(*fl, "psrlqq");
    addRemoveLastLetterTerm(*fl, "psrlwq");
    addRemoveLastLetterTerm(*fl, "psubbq");
    addRemoveLastLetterTerm(*fl, "psubdq");
    addRemoveLastLetterTerm(*fl, "psubqq");
    addRemoveLastLetterTerm(*fl, "psubsbq");
    addRemoveLastLetterTerm(*fl, "psubswq");
    addRemoveLastLetterTerm(*fl, "psubusbq");
    addRemoveLastLetterTerm(*fl, "psubuswq");
    addRemoveLastLetterTerm(*fl, "psubwq");
    addRemoveLastLetterTerm(*fl, "punpckhbwq");
    addRemoveLastLetterTerm(*fl, "punpckhdqq");
    addRemoveLastLetterTerm(*fl, "punpckhwdq");
    addRemoveLastLetterTerm(*fl, "punpcklbwl");
    addRemoveLastLetterTerm(*fl, "punpckldql");
    addRemoveLastLetterTerm(*fl, "punpcklwdl");
    addRemoveLastLetterTerm(*fl, "pxorq");
    addRemoveLastLetterTerm(*fl, "pabsb");
    addRemoveLastLetterTerm(*fl, "pabsd");
    addRemoveLastLetterTerm(*fl, "pabsw");
    addRemoveLastLetterTerm(*fl, "pavgusb");
    addRemoveLastLetterTerm(*fl, "phaddd");
    addRemoveLastLetterTerm(*fl, "phsubd");
    addRemoveLastLetterTerm(*fl, "phsubw");
    addRemoveLastLetterTerm(*fl, "pmaddubsw");
    addRemoveLastLetterTerm(*fl, "pmulhrsw");
    addRemoveLastLetterTerm(*fl, "pmulhrw");
    addRemoveLastLetterTerm(*fl, "pshufb");
    addRemoveLastLetterTerm(*fl, "psignb");
    addRemoveLastLetterTerm(*fl, "psignd");
    addRemoveLastLetterTerm(*fl, "psignw");
    addRemoveLastLetterTerm(*fl, "palignrq");
    addRemoveLastLetterTerm(*fl, "pandq");
    addRemoveLastLetterTerm(*fl, "pextrbb");
    addRemoveLastLetterTerm(*fl, "pextrdl");
    addRemoveLastLetterTerm(*fl, "pinsrbb");
    addRemoveLastLetterTerm(*fl, "pinsrdl");
    addRemoveLastLetterTerm(*fl, "pmovsxbdl");
    addRemoveLastLetterTerm(*fl, "pmovsxbqw");
    addRemoveLastLetterTerm(*fl, "pmovzxbdl");
    addRemoveLastLetterTerm(*fl, "pmovzxbqw");
    
    addRemoveLastLetterTerm(*fl, "pextrww");
    addRemoveLastLetterTerm(*fl, "phaddswq");
    addRemoveLastLetterTerm(*fl, "phaddwq");
    addRemoveLastLetterTerm(*fl, "phsubswq");
    addRemoveLastLetterTerm(*fl, "pi2fdq");
    addRemoveLastLetterTerm(*fl, "pi2fwq");
    addRemoveLastLetterTerm(*fl, "pmovsxdqq");
    addRemoveLastLetterTerm(*fl, "pmovzxbwq");
    addRemoveLastLetterTerm(*fl, "pmovzxdqq");
    addRemoveLastLetterTerm(*fl, "pswapdq");
    
    return fl;
}

static FindList* initRemoveLastLetterFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addRemoveLastLetterTerm(*fl, "cflush");
    addRemoveLastLetterTerm(*fl, "clflush");
    addRemoveLastLetterTerm(*fl, "vmclear");
    addRemoveLastLetterTerm(*fl, "kmovbb");
    return fl;
}

static FindList* initStrInsnDressingFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addReplaceTerm(*fl, "stosqq", "stosq");
    addReplaceTerm(*fl, "movsqq", "movsq");
    addReplaceTerm(*fl, "scasqq", "scasq");
    addReplaceTerm(*fl, "insqq", "insq");
    addReplaceTerm(*fl, "outsqq", "outsq");
    addReplaceTerm(*fl, "lodsqq", "lodsq");
    addReplaceTerm(*fl, "cmpsqq", "cmpsq");
    addReplaceTerm(*fl, "stosll", "stosl");
    addReplaceTerm(*fl, "movsll", "movsl");
    addReplaceTerm(*fl, "scasll", "scasl");
    addReplaceTerm(*fl, "insll", "insl");
    addReplaceTerm(*fl, "outsll", "outsl");
    addReplaceTerm(*fl, "lodsll", "lodsl");
    addReplaceTerm(*fl, "cmpsll", "cmpsl");
    return fl;
}

static FindList* initOpcodeDressingFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addReplaceTerm(*fl, "upq ", "up ");
    addReplaceTerm(*fl, "bx ", "b ");
    addReplaceTerm(*fl, "wx ", "w ");
    addReplaceTerm(*fl, "dx ", "d ");
    addReplaceTerm(*fl, "qx ", "q ");
    addReplaceTerm(*fl, "by ", "b ");
    addReplaceTerm(*fl, "bz ", "b ");
    addReplaceTerm(*fl, "wl ", "w ");
    addReplaceTerm(*fl, "wq ", "w ");
    addReplaceTerm(*fl, "wy ", "w ");
    addReplaceTerm(*fl, "wz ", "w ");
    addReplaceTerm(*fl, "ww ", "w ");
    addReplaceTerm(*fl, "sdl ", "sd ");
    addReplaceTerm(*fl, "dy ", "d ");
    addReplaceTerm(*fl, "dz ", "d ");
    addReplaceTerm(*fl, "qql ", "qq ");
    addReplaceTerm(*fl, "pdq ", "pd ");
    addReplaceTerm(*fl, "sdq ", "sd ");
    addReplaceTerm(*fl, "sbq ", "sb ");
    addReplaceTerm(*fl, "dbq ", "db ");
    addReplaceTerm(*fl, "wdq ", "wd ");
    addReplaceTerm(*fl, "qz ", "q ");
    addReplaceTerm(*fl, "rdl ", "rd ");
    addReplaceTerm(*fl, "ldl ", "ld ");
    addReplaceTerm(*fl, "dql ", "dq ");
    addReplaceTerm(*fl, "wdl ", "wd ");
    addReplaceTerm(*fl, "sdl ", "sl ");
    addReplaceTerm(*fl, "fdl ", "fd ");
    addReplaceTerm(*fl, "pdl ", "pd ");
    addReplaceTerm(*fl, "bdl ", "bd ");
    addReplaceTerm(*fl, "wql ", "wq ");
    addReplaceTerm(*fl, "siq ", "si ");
    addReplaceTerm(*fl, "sil ", "si ");
    addReplaceTerm(*fl, "piq ", "pi ");
    addReplaceTerm(*fl, "psq ", "ps ");
    addReplaceTerm(*fl, "psx ", "ps ");
    addReplaceTerm(*fl, "psy ", "ps ");
    addReplaceTerm(*fl, "psl ", "ps ");
    addReplaceTerm(*fl, "pdz ", "pd ");
    addReplaceTerm(*fl, "nrq ", "nr ");
    addReplaceTerm(*fl, "bqw ", "bq ");
    addReplaceTerm(*fl, "nqq ", "nq ");
    addReplaceTerm(*fl, "sww", "sw");
    addReplaceTerm(*fl, "ssl", "ss");
    addReplaceTerm(*fl, "x2q ", "x2 ");
    addReplaceTerm(*fl, "x4q ", "x4 ");
    addReplaceTerm(*fl, "x2l ", "x2 ");
    addReplaceTerm(*fl, "x4l ", "x4 ");
    addReplaceTerm(*fl, "movqq ", "movq ");
    addReplaceTerm(*fl, "movntqq ", "movntq ");
    addReplaceTerm(*fl, "pcmpgtbq", "pcmpgtb");
    addReplaceTerm(*fl, "stmxcsrl", "stmxcsr");
    addReplaceTerm(*fl, "ldmxcsrl", "ldmxcsr");
    addReplaceTerm(*fl, "pextrbb", "pextrb");
    addReplaceTerm(*fl, "sxd ", "slq ");
    addReplaceTerm(*fl, "stosd", "stosl");
    addReplaceTerm(*fl, "stosdl", "stosl");
    addReplaceTerm(*fl, "fld ", "fldt ");
    addReplaceTerm(*fl, "movdl", "movd");
    addReplaceTerm(*fl, "iretd", "iretl");
    addReplaceTerm(*fl, "scasbb", "scasb");
    addReplaceTerm(*fl, "stosbb", "stosb");
    addReplaceTerm(*fl, "stosd", "stosl");
    addReplaceTerm(*fl, "scasd", "scasl");
    addReplaceTerm(*fl, "scasdl", "scasl");
    addReplaceTerm(*fl, "movsbb", "movsb");
    addReplaceTerm(*fl, "insbb", "insb");
    addReplaceTerm(*fl, "insww", "insw");
    addReplaceTerm(*fl, "outsww", "outsw");
    addReplaceTerm(*fl, "insdl", "insl");
    addReplaceTerm(*fl, "outsbb", "outsb");
    addReplaceTerm(*fl, "outsdl", "outsl");
    addReplaceTerm(*fl, "lodsd", "lodsl");
    addReplaceTerm(*fl, "lodsdl", "lodsl");
    addReplaceTerm(*fl, "lodsbb", "lodsb");
    addReplaceTerm(*fl, "cmpsbb", "cmpsb");
    addReplaceTerm(*fl, "popfqq", "popfq");
    addReplaceTerm(*fl, "pushfqq", "pushfq");
    addReplaceTerm(*fl, "invlpgb", "invlpg");
    addReplaceTerm(*fl, "lcallq", "lcall");
    addReplaceTerm(*fl, "maskmovqq", "maskmovq");
    addReplaceTerm(*fl, "fyl2 %st(1), %st(0)", "fyl2x");
    return fl;
}

static void fixExtraOpcodeDressing(char* buf, int bufLen) {
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

static void removeExtraAddr32(char* buf, int bufLen) {
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

static void removeExtraData16(char* buf, int bufLen) {
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

static void fixFloatSuffixes(char* buf, int bufLen) {
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

static void addImplicitRegs(char* buf, int bufLen) {
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

static void removeImplicitEnclOperands(char* buf, int bufLen) {
    if (!strncmp(buf, "encl", 4)) {
        *(buf + 5) = '\0';
    }
}

static FindList* initSwapXEDOperandOrderFindList() {
    FindList* fl = new FindList(FIND_LIST_SIZE);
    addOperandSwapTerm(*fl, "vrange", 1, 2);
    addOperandSwapTerm(*fl, "vfix", 1, 2);
    addOperandSwapTerm(*fl, "vreduce", 1, 2);
    addOperandSwapTerm(*fl, "vcmp", 1, 2);
    return fl;
}

static void swapXEDOperandOrder(char* buf, int bufLen) {
    static FindList* fl = initSwapXEDOperandOrderFindList();
    fl->process(buf, bufLen);
}

static void removeLockColon(char* buf, int bufLen) {
    std::string str = std::string(buf);
    auto index = str.find("lock :");
    if (index != std::string::npos) {
        buf[index + 5] = ' ';
    }
}

void xed_x86_32_norm(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    fixStRegs(buf, bufLen);
    fixMmxRegs(buf, bufLen);
    fixExtraOpcodeDressing(buf, bufLen);
    fixVexTrailingX(buf, bufLen);
    fixVexMaskOperations(buf, bufLen);
    removeUnusedOverridePrefixes(buf, bufLen);
    removeImplicitEnclOperands(buf, bufLen);
    cleanX86NOP(buf, bufLen);
    removeExtraData16(buf, bufLen);
    removeExtraAddr32(buf, bufLen);
    fixFloatSuffixes(buf, bufLen);
    removeLockColon(buf, bufLen);
    fixPrefetchSuffix(buf, bufLen);
    fixPFInsnSuffix(buf, bufLen);
    signedOperands(buf, bufLen);
    removeX86Hints(buf, bufLen);
    cleanSpaces(buf, bufLen);
    addImplicitRegs(buf, bufLen);
    addMissing0x0(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    fixMaskName(buf, bufLen);
    removeImplicitST0(buf, bufLen);
}

int xed_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {
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

