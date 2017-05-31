
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

#include "FindList.h"

FindList::FindList(uint32_t size) {
    this->size = size;
    nTerms = 0;
    minStrLen = INT_MAX;
    maxStrLen = INT_MIN;
    terms = (FLEntry*)malloc(size * sizeof(*terms));
    for (uint32_t i = 0; i < size; i++) {
        terms[i].str = NULL;
    }
    assert(terms != NULL);
}

FindList::~FindList() {
    free(terms);
}
    
void FindList::addTerm(const char* val, void (*func)(char* buf, int bufLen, void* arg), void* funcArg) {
    int len = strlen(val);
    assert(len != 0);
    if (len < minStrLen) {
        minStrLen = len;
    }
    if (len > maxStrLen) {
        maxStrLen = len;
    }
    uint32_t freeIndex = hash(val);
    while (terms[freeIndex].str != NULL) {
        freeIndex = (freeIndex * 3 + 1) % size;
    }
    terms[freeIndex].str = strdup(val);
    terms[freeIndex].func = func;
    terms[freeIndex].arg = funcArg;
    terms[freeIndex].len = strlen(val);
}
    
void FindList::process(char* buf, int bufLen) {
    char* cur = buf;
    char* minStrPtr = buf + minStrLen;
    while (*cur && cur < minStrPtr) {
        cur++;
    }
    if (!*cur) {
        return;
    }
    char* bufEnd = buf + bufLen;
    char* base = buf;
    while (base[minStrLen - 1]) {
        cur = base;
        minStrPtr = base + minStrLen - 1;
        uint32_t curHash = 0;
        uint32_t factor = 31;
        while (cur < minStrPtr) {
            curHash = (curHash + factor * *cur) % size;
            factor *= 31;
            cur++;
        }
        int curLen = minStrLen - 1;
        while (*cur && curLen < maxStrLen) {
            curLen++;
            curHash = (curHash + factor * *cur) % size;
            factor *= 31;
            uint32_t index = curHash;
            FLEntry term = terms[index];
            bool done = false;
            bool matched = false;
            while (!done) {
                term = terms[index];
                if (term.str == NULL) {
                    done = true;
                } else if (!strncmp(term.str, base, curLen) && (int)strlen(term.str) == curLen) {
                    done = true;
                    matched = true;
                }
                index = (index * 3 + 1) % size;
            }
            if (matched) {
                term.func(base, bufEnd - base, term.arg);
            }
            cur++;
        }
        base++;
    }
}

uint32_t FindList::hash(const char* str) {
    uint32_t result = 0;
    uint32_t factor = 31;
    while (*str) {
        result = (result + factor * *str) % size;
        factor *= 31;
        ++str;
    }
    return result;
}
