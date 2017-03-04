
#ifndef _NORMALIZATION_H_
#define _NORMALIZATION_H_

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <cctype>

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

#endif // _NORMALIZATION_H_
