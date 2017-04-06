
#ifndef _NORMALIZATION_H_
#define _NORMALIZATION_H_

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <cctype>

#include "FindList.h"

bool isAarch64SysRegInsn(char* inst, int nBytes, char* buf, int bufLen);

void cleanSpaces       (char* buf, int bufLen);
void toLowerCase       (char* buf, int bufLen);
void trimHexZeroes     (char* buf, int bufLen);
void trimHexFs         (char* buf, int bufLen);
void spaceAfterCommas  (char* buf, int bufLen);
void removeComments    (char* buf, int bufLen);
void decToHexConstants (char* buf, int bufLen);
void removePounds      (char* buf, int bufLen);
void place0x           (char* buf, int bufLen);
void removeHexBrackets (char* buf, int bufLen);
void removeADRPZeroes  (char* buf, int bufLen);
void commaBeforeSpace  (char* buf, int bufLen);
void removeEmptyParens (char* buf, int bufLen);
void removePoundComment(char* buf, int bufLen);
void fixStRegs         (char* buf, int bufLen);
void cleanX86NOP       (char* buf, int bufLen);

typedef struct ReplaceParam {
    size_t len;
    const char* newStr;
} ReplacePair;

void addReplaceTerm(FindList& fl, const char* oldStr, const char* newStr);
void flReplaceFunc(char* buf, int bufLen, void* rParam);

#endif // _NORMALIZATION_H_
