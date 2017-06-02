
#ifndef _NORMALIZATION_H_
#define _NORMALIZATION_H_

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <cctype>

#include "StringUtils.h"
#include "FindList.h"

namespace Normalization {

    void applyGenericNormalization(char* buf, int bufLen);

    void cleanSpaces     (char* buf, int bufLen);
    void toLowerCase     (char* buf, int bufLen);
    void spaceAfterCommas(char* buf, int bufLen);
    void removeComments  (char* buf, int bufLen);

    void addAppend0x0IfEndsTerm(FindList& fl, const char* str);
    void addRemoveLastLetterTerm(FindList& fl, const char* str);
    void addOperandSwapTerm(FindList& fl, const char* opcode, size_t pos1, size_t pos2);
    void addReplaceTerm(FindList& fl, const char* oldStr, const char* newStr);
}

typedef struct ReplaceParam {
    size_t len;
    const char* newStr;
} ReplacePair;

typedef struct OperandSwapParam {
    size_t pos1;
    size_t pos2;
} OperandSwap;

#endif // _NORMALIZATION_H_
