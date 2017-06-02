
#include <iostream>
#include <string.h>
#include "Normalization.h"

void flReplaceFunc(char* buf, int bufLen, void* repParam);
    
void Normalization::applyGenericNormalization(char* buf, int bufLen) {
    cleanSpaces(buf, bufLen);
    toLowerCase(buf, bufLen);
    spaceAfterCommas(buf, bufLen);
    removeComments(buf, bufLen);
}

void Normalization::cleanSpaces(char* buf, int bufLen) {
    bool inSpace = true;
    char* cur = buf;
    char* place = buf;
    while (*cur) {
        if (isspace(*cur)) {
            if (!inSpace) {
                inSpace = true;
                *place = ' ';
                place++;
            }
        } else {
            inSpace = false;
            *place = *cur;
            place++;
        }
        cur++;
    }
    if (*(place - 1) == ' ') {
        place--;
    }
    *place = 0;
}

void Normalization::toLowerCase(char* buf, int bufLen) {
    char* cur = buf;
    while (*cur) {
        if (isupper(*cur)) {
            *cur += 32;
        }
        cur++;
    }
}

void Normalization::spaceAfterCommas(char* buf, int bufLen) {
    char tmpBuf[bufLen];
    char* tmp = &tmpBuf[0];
    char* cur = buf;
    char* place = tmp;

    while (*cur && place < tmp + bufLen) {
        *place = *cur;
        place++;
        if (*cur == ',' && *(cur + 1) != ' ') {
            *place = ' ';
            place++;
        }
        cur++;
    }
    *place = 0;

    strncpy(buf, tmp, bufLen);
}

void Normalization::removeComments(char* buf, int bufLen) {
   char* cur = buf;
   while (*cur && !(*cur == '/' && *(cur + 1) == '/')) {
      cur++;
   }
   *cur = 0;
   // Remove a trailing space if one existed.
   if (cur != buf && isspace(*(cur - 1))) {
      *(cur - 1) = 0;
   }
}

void flOperandSwapFunc(char* buf, int bufLen, void* oSwapParam) {
    OperandSwapParam* osParam = (OperandSwapParam*)oSwapParam;
    char buf1[bufLen];
    char between[bufLen];
    char buf2[bufLen];
    bool inParens = false;
    char* place1;
    char* place2;
    size_t len1;
    size_t len2;
    size_t betweenLen;
    char* cur = buf;
    size_t curPos = 0;
    //std::cerr << "BEFORE: " << buf << "\n";
    while (*cur && !isspace(*cur)) {
        ++cur;
    }
    while (curPos < osParam->pos1) {
        while (*cur && (inParens || !isspace(*cur))) {
            if (*cur == '(') {
                inParens = true;
            }
            if (*cur == ')') {
                inParens = false;
            }
            ++cur;
        }
        if (!*cur) {
            return;
        }
        ++cur;
        ++curPos;
        //std::cerr << "Pos " << curPos << " at " << cur << "\n";
    }
    place1 = cur;
    while (*cur && (inParens || *cur != ',')) {
        if (*cur == '(') {
            inParens = true;
        }
        if (*cur == ')') {
            inParens = false;
        }
        ++cur;
    }
    if (*cur != ',' || *(cur + 1) != ' ') {
        return;
    }
    len1 = cur - place1;
    strncpy(buf1, place1, len1);
    buf1[len1] = '\0';
    //std::cerr << "Operand " << osParam->pos1 << " = " << buf1 << "\n";
    while (curPos < osParam->pos2) {
        while (*cur && (inParens || !isspace(*cur))) {
            if (*cur == '(') {
                inParens = true;
            }
            if (*cur == ')') {
                inParens = false;
            }
            ++cur;
        }
        if (!*cur) {
            return;
        }
        ++cur;
        ++curPos;
        //std::cerr << "Pos " << curPos << " at " << cur << "\n";
    }
    if (!*cur) {
        return;
    }
    betweenLen = cur - (place1 + len1);
    strncpy(between, place1 + len1, betweenLen);
    between[betweenLen] = '\0';
    //std::cerr << "Between = " << between << "\n";
    place2 = cur;
    while (*cur && (inParens || (*cur != ',' && *cur != '{'))) {
        if (*cur == '(') {
            inParens = true;
        }
        if (*cur == ')') {
            inParens = false;
        }
        ++cur;
    }
    len2 = cur - place2;
    strncpy(buf2, place2, len2);
    buf2[len2] = '\0';
    //std::cerr << "Operand " << osParam->pos2 << " = " << buf2 << "\n";
    strncpy(place1, buf2, len2);
    strncpy(place1 + len2, between, betweenLen);
    strncpy(place1 + len2 + betweenLen, buf1, len1);
    //std::cerr << "AFTER:  " << buf << "\n";
}

void Normalization::addOperandSwapTerm(FindList& fl, const char* opcode, size_t pos1, size_t pos2) {
    OperandSwapParam* osParam = new OperandSwapParam;
    osParam->pos1 = pos1;
    osParam->pos2 = pos2;
    fl.addTerm(opcode, &flOperandSwapFunc, (void*)osParam);
}

void flAppend0x0IfEndsFunc(char* buf, int bufLen, void* unused) {
    char* cur = buf;
    ++cur;
    while (*cur && !isspace(*cur) && *cur != ',') {
        ++cur;
    }
    if (!(*cur)) {
        strncpy(cur, " 0x0", bufLen - (cur - buf));
    }
}

void Normalization::addAppend0x0IfEndsTerm(FindList& fl, const char* str) {
    fl.addTerm(str, &flAppend0x0IfEndsFunc, NULL);
}

void flRemoveLastLetterFunc(char* buf, int bufLen, void* unused) {
    char* cur = buf;
    ++cur;
    while (*cur && !isspace(*cur) && *cur != ',') {
        ++cur;
    }
    *(cur - 1) = ' ';
}

void Normalization::addRemoveLastLetterTerm(FindList& fl, const char* str) {
    fl.addTerm(str, &flRemoveLastLetterFunc, NULL);
}

void Normalization::addReplaceTerm(FindList& fl, const char* oldStr, const char* newStr) {
    ReplaceParam* rParam = new ReplaceParam;
    rParam->len = strlen(oldStr);
    rParam->newStr = strdup(newStr);
    fl.addTerm(oldStr, &flReplaceFunc, (void*)rParam);
}

void flReplaceFunc(char* buf, int bufLen, void* repParam) {
    ReplaceParam* rParam = (ReplaceParam*)repParam;
    size_t uBufLen = bufLen;
    if (uBufLen < rParam->len) {
        std::cerr << "ERROR: Buffer length too short for FindList replacement!\n";
        return;
    }
    
    int newLen = strlen(rParam->newStr);
    char* place = buf + newLen;
    char* cur = buf + rParam->len;
    if (place < cur) {
        while (*cur) {
            *place = *cur;
            ++place;
            ++cur;
        }
        *place = *cur;
    } else if (place > cur) {
        while (*cur) {
            ++cur;
            ++place;
        }
        char* endPtr = buf + newLen;
        while (place >= endPtr) {
            *place = *cur;
            --cur;
            --place;
        }
    }
    strncpy(buf, rParam->newStr, newLen);
}

