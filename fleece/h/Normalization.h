
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

bool isAarch64SysRegInsn(char* inst, int nBytes, char* buf, int bufLen);

void cleanSpaces       (char* buf, int bufLen);
void toLowerCase       (char* buf, int bufLen);
void trimHexZeroes     (char* buf, int bufLen);
void trimHexFs         (char* buf, int bufLen);
void spaceAfterCommas  (char* buf, int bufLen);
void removeComments    (char* buf, int bufLen);
void hexToDecConstants (char* buf, int bufLen);
void decToHexConstants (char* buf, int bufLen);
void removePounds      (char* buf, int bufLen);
void addImpliedX86Index(char* buf, int bufLen);
void addMissing0x0     (char* buf, int bufLen);
void place0x           (char* buf, int bufLen);
void removeHexBrackets (char* buf, int bufLen);
void removeADRPZeroes  (char* buf, int bufLen);
void commaBeforeSpace  (char* buf, int bufLen);
void removeImplicitK0  (char* buf, int bufLen);
void removeX86Hints    (char* buf, int bufLen);
void removeEmptyParens (char* buf, int bufLen);
void removeUnusedRepPrefixes(char* buf, int bufLen);
void removeUnusedOverridePrefixes(char* buf, int bufLen);
void removeUnused64BitSegRegs(char* buf, int bufLen);
void removePoundComment(char* buf, int bufLen);
void signedOperands    (char* buf, int bufLen);
void removeImplicitST0 (char* buf, int bufLen);
void fixStRegs         (char* buf, int bufLen);
void cleanX86NOP       (char* buf, int bufLen);
void fixCallSuffix     (char* buf, int bufLen);

typedef struct ReplaceParam {
    size_t len;
    const char* newStr;
} ReplacePair;

typedef struct OperandSwapParam {
    size_t pos1;
    size_t pos2;
} OperandSwap;

void addAppend0x0IfEndsTerm(FindList& fl, const char* str);
void addRemoveLastLetterTerm(FindList& fl, const char* str);
void addOperandSwapTerm(FindList& fl, const char* opcode, size_t pos1, size_t pos2);
void addReplaceTerm(FindList& fl, const char* oldStr, const char* newStr);
void flReplaceFunc(char* buf, int bufLen, void* rParam);

#endif // _NORMALIZATION_H_
