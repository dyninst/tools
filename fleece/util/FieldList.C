
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

#include <iostream>
#include "FieldList.h"

bool FieldList::isSeparator(char c) {
    static std::string sepString = " ,\t[]{}():-$#*\n";

    return sepString.find(c) != std::string::npos;
}

FieldList::FieldList(const char* buf) {
    nFields = 0;

    const char* cur = buf;
    bool inField = !isSeparator(*cur);

    // Iterate over the string counting the number of non-empty fields separated
    // by spaces.
    while (*cur) {
        if (isSeparator(*cur)) {
            if (inField) {
                nFields++;
            }
            inField = false;
        } else {
            inField = true;
        }
        cur++;
    }
   
    // If we ended without a space and hit at least one non-space character,
    // then we need to count the last field as well.
    if (inField) {
        nFields++;
     }

    // Now that we know how many fields we will have, we can properly allocate
    // pointers to each.
    fields = (char**)malloc(nFields * sizeof(*fields));
    assert(fields != NULL);
    separators = (char**)malloc((nFields + 1) * sizeof(*separators));
    assert(separators != NULL);

    for (unsigned int i = 0; i < nFields; i++) {
        fields[i] = NULL;
        separators[i] = NULL;
    }
    separators[nFields] = NULL;

    // Iterate through the string again, making an array of all the fields.
    cur = buf;
    int curField = 0;
    const char* curStart = buf;
    inField = !isSeparator(*cur);
    while (*cur) {
        bool isSep = isSeparator(*cur);
        if (isSep == inField) {
            int strLen = cur - curStart;
            char* newStr = (char*)malloc(strLen + 1);
            assert(newStr != NULL);
            strncpy(newStr, curStart, strLen);
            newStr[strLen] = '\0';
            if (inField) {
                fields[curField] = newStr;
                curField++;
            } else {
                separators[curField] = newStr;
            }
            curStart = cur;
        }
        inField = !isSep;
        cur++;
    }

    int strLen = cur - curStart;
    char* newStr = (char*)malloc(strLen + 1);
    assert(newStr != NULL);
    strncpy(newStr, curStart, strLen);
    newStr[strLen] = '\0';
    
    if (inField) {
        fields[curField] = newStr;
    } else {
        separators[curField] = newStr;
    }

    if (separators[0] == NULL) {
        separators[0] = (char*)malloc(1);
        assert(separators[0] != NULL);
        separators[0][0] = '\0';
    }

    if (separators[nFields] == NULL) {
        separators[nFields] = (char*)malloc(1);
        assert(separators[nFields] != NULL);
        separators[nFields][0] = '\0';
    }
    //std::cout << "Field list from: " << buf << "\n";
    //print(stdout);
}

FieldList::~FieldList() {
    for (size_t i = 0; i < nFields; i++) {
        free(fields[i]);
        free(separators[i]);
    }
    free(separators[nFields]);

    free(fields);
    free(separators);
}

unsigned int FieldList::size() {
    return nFields;
}

unsigned int FieldList::getTotalBytes() {
    unsigned int totalBytes = 1; // Start at 1 to include the null terminator.
    for (unsigned int i = 0; i < nFields; i++) {
        totalBytes += strlen(fields[i]);
        totalBytes += strlen(separators[i]);
    }
    totalBytes += strlen(separators[nFields]);
    return totalBytes;
}

void FieldList::fillBuf(char* buf, unsigned int len) {
    char* bufEnd = buf + len - 1;
    char* cur;
    for (unsigned int i = 0; i < nFields && buf < bufEnd; i++) {
        cur = separators[i];
        while (*cur && buf < bufEnd) {
            *buf = *cur;
            cur++;
            buf++;
        }
      
        cur = fields[i];
        while (*cur && buf < bufEnd) {
            *buf = *cur;
            cur++;
            buf++;
        }
    }
    cur = separators[nFields];
    while (*cur && buf < bufEnd) {
        *buf = *cur;
        cur++;
        buf++;
    }
    *buf = '\0';
}

bool FieldList::hasField(char* field) {
    for (size_t i = 0; i < nFields; i++) {
        if (!strcmp(field, fields[i])) {
            return true;
        }
    }
    return false;
}

char* FieldList::getField(unsigned int index) {
    if (index >= nFields) {
        return NULL;
    }
    return fields[index];
}
    
void FieldList::setField(unsigned int index, const char* newField) {
    assert(index < nFields);
    free(fields[index]);
    fields[index] = strdup(newField);
}

bool FieldList::hasError() {
    for (size_t i = 0; i < nFields; i++) {
        if (signalsError(fields[i])) {
            return true;
        }
    }
    return false;
}

void FieldList::stripDigits() {
   for (size_t i = 0; i < nFields; i++) {
      strStripDigits(fields[i]);
   }
}

void FieldList::stripHex() {
   for (size_t i = 0; i < nFields; i++) {
      strStripHex(fields[i]);
   }
}

void FieldList::print(FILE* f) {
    fprintf(f, "Fields:\n");
    for (unsigned int i = 0; i < nFields; i++) {
        fprintf(f, "\t%s\n", fields[i]);
    }
    fprintf(f, "Separators:\n");
    for (unsigned int i = 0; i <= nFields; i++) {
        fprintf(f, "\t%s\n", separators[i]);
    }
}
