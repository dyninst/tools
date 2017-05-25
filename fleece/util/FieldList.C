
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

#define MAX_FIELDS 15

unsigned long long FieldList::totalHasErrTime = 0;

static bool* createSeparatorArray() {
    bool* sepArray = new bool[256];
    for (int i = 0; i < 256; ++i) {
        sepArray[i] = false;
    }
    sepArray[' '] = true;
    sepArray[','] = true;
    sepArray[':'] = true;
    sepArray['['] = true;
    sepArray[']'] = true;
    sepArray['{'] = true;
    sepArray['}'] = true;
    sepArray['('] = true;
    sepArray[')'] = true;
    sepArray['$'] = true;
    sepArray['#'] = true;
    sepArray['*'] = true;
    sepArray['+'] = true;
    sepArray['-'] = true;
    sepArray['\t'] = true;
    sepArray['\n'] = true;
    return sepArray;
}

bool FieldList::isSeparator(char c) {
    static bool* sepArray = createSeparatorArray();
    return sepArray[(int)c];
}

size_t FieldList::detectNumFields(const char* buf) {
    size_t nFields = 0;
    
    // The string does not start in a field if the first character is a separator.
    bool inField = !isSeparator(*buf);
    
    // Iterate over the string counting the number of fields with at least one separator between 
    // each.
    const char* cur = buf;
    while (*cur) {
        if (isSeparator(*cur)) {
            if (inField) {

                // This if statement matches everything except the exponent part of a floating point immediate.
                // For example, the '-' in "1.23e-5" will not appear to be a separator because it is a plus
                // or minus, it is preceeeded by an 'e' and it is followed by a digit.
                if ((*cur != '+' && *cur != '-') || 
                    (cur == buf || *(cur - 1) != 'e') || 
                    !isdigit(*(cur + 1))) {

                    ++nFields;
                    inField = false;
                }
            }
        } else {
            inField = true;
        }
        ++cur;
    }
   
    // If we ended without a space and hit at least one non-space character, then we need to count
    // the last field as well.
    if (inField) {
        ++nFields;
    }

    return nFields;
}

void FieldList::allocateFieldsAndSeparators() {
    fields = new char*[MAX_FIELDS/*nFields*/];
    separators = new char*[MAX_FIELDS + 1/*nFields + 1*/];
    assert(fields != NULL && separators != NULL);
}

bool shouldFieldIncludeDash(const char* strStart, const char* strEnd) {
    char* endPtr;
    strtod(strStart, &endPtr);
    return endPtr == strEnd;
}

void FieldList::initFieldsAndSeparators(const char* buf) {
    size_t curField = 0;
    const char* cur = buf;
    const char* strStart = buf;
    bool inField = !isSeparator(*buf);
    char* lastSepChar = NULL;

    // If we start out the game in a field, the first separator will be and empty string.
    if (inField) {
        separators[0] = new char[1];
        assert(separators[0] != NULL);
        separators[0][0] = '\0';
        lastSepChar = &(separators[0][0]);
    }

    // Iterate through the string, filling the allocated fields and separators.
    while (*cur) {

        bool isSep = isSeparator(*cur);
                
        // This if statement matches the exponent part of a floating point immediate.
        // For example, the '-' in "1.23e-5" will not appear to be a separator because it is a plus
        // or minus, it is preceeeded by an 'e' and it is followed by a digit.
        if (isSep && inField &&
            (*cur == '+' || *cur == '-') &&
            (cur != buf && *(cur - 1) == 'e') &&
            isdigit(*(cur + 1))) {

            isSep = false;
        }

        // If we change between in a field or in a separator, we just finished a field or
        // separator, so we need to allocate one and copy it.
        if (isSep == inField) {
            if (inField) {
                if (*lastSepChar == '-' && shouldFieldIncludeDash(strStart, cur)) {
                    --strStart;
                    *lastSepChar = '\0';
                }
                int len = cur - strStart;
                char* newStr = new char[len + 1];
                strncpy(newStr, strStart, len);
                newStr[len] = '\0'; // This should be redundant, but it's good to be safe.
                fields[curField] = newStr;
                curField++;
                if (curField == MAX_FIELDS) {
                    std::cout << "ERROR: MAXED ON FIELDS!\n";
                }
            } else {
                int len = cur - strStart;
                char* newStr = new char[len + 1];
                strncpy(newStr, strStart, len);
                newStr[len] = '\0'; // This should be redundant, but it's good to be safe.
                separators[curField] = newStr;
                lastSepChar = &(separators[curField][len - 1]);
            }
            strStart = cur;
        }
        inField = !isSep;
        ++cur;
    }
    
    // If we ended our parsing in a field, we need to allocate an empty string for the last
    // separator,
    if (inField) {
        if (*lastSepChar == '-' && shouldFieldIncludeDash(strStart, cur)) {
            --strStart;
            *lastSepChar = '\0';
        }
        int len = cur - strStart;
        char* newStr = new char[len + 1];
        strncpy(newStr, strStart, len);
        newStr[len] = '\0';
        fields[curField] = newStr;
        ++curField;
        separators[curField] = new char[1];
        assert(separators[curField] != NULL);
        separators[curField][0] = '\0';
    } else {
        int len = cur - strStart;
        char* newStr = new char[len + 1];
        strncpy(newStr, strStart, len);
        newStr[len] = '\0';
        separators[curField] = newStr;
    }

    nFields = curField;
    //std::cout << "Field list from: " << buf << "\n";
    //print(stdout);
}

FieldList::FieldList(const char* buf) {
    allocateFieldsAndSeparators();
    initFieldsAndSeparators(buf);
}

FieldList::~FieldList() {
    for (size_t i = 0; i < nFields; i++) {
        delete [] fields[i];
        delete [] separators[i];
    }
    delete [] separators[nFields];
    delete [] fields;
    delete [] separators;
}

size_t FieldList::size() const {
    return nFields;
}

size_t FieldList::getTotalBytes() {
    unsigned int totalBytes = 1; // Start at 1 to include the null terminator.
    for (unsigned int i = 0; i < nFields; i++) {
        totalBytes += strlen(fields[i]);
        totalBytes += strlen(separators[i]);
    }
    totalBytes += strlen(separators[nFields]);
    return totalBytes;
}

void FieldList::fillBuf(char* buf, size_t len) const {
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

bool FieldList::hasField(const char* field) const {
    for (size_t i = 0; i < nFields; i++) {
        if (!strcmp(field, fields[i])) {
            return true;
        }
    }
    return false;
}

const char* FieldList::getField(size_t index) const {
    if (index >= nFields) {
        return NULL;
    }
    return (const char*)fields[index];
}
    
void FieldList::setField(size_t index, const char* newField) {
    assert(index < nFields);
    int len = strlen(newField) + 1;
    delete [] fields[index];
    fields[index] = new char [len];
    strncpy(fields[index], newField, len);
}

bool FieldList::hasError() const {
    for (size_t i = 0; i < nFields; i++) {
        if (signalsError(fields[i])) {
            return true;
        }
    }
    return false;
}

void FieldList::stripDigits() {
    for (size_t i = 0; i < nFields; i++) {
        char first = *(fields[i]);
        if (isdigit(first) || first == '-') {
            char* endPtr;
            strtod(fields[i], &endPtr);
            if (*endPtr == '\0') {
                if (strlen(fields[i]) < 3) {
                    delete [] fields[i];
                    fields[i] = new char[4];
                }
                strncpy(fields[i], "IMM", 4);
            }
        }
    }
}

void FieldList::stripHex() {
    for (size_t i = 0; i < nFields; i++) {
        char* field = fields[i];
        if (*field == '-') {
            ++field;
        }
        if (*field == '0' && *(field + 1) == 'x') {
            if (strlen(fields[i]) < 3) {
                delete [] fields[i];
                fields[i] = new char[4];
            }
            strncpy(fields[i], "IMM", 4);
        }
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

void FieldList::printInsn(FILE* f) {
    for (unsigned int i = 0; i < nFields; i++) {
        fprintf(f, "%s%s", separators[i], fields[i]);
    }
    fprintf(f, "%s", separators[nFields]);
}

bool FieldList::isFieldImm(size_t whichField) {
    char* endPtr;
    strtod(fields[whichField], &endPtr);
    if (*endPtr == '\0') {
        return true;
    }
    char* field = fields[whichField];
    if (*field == '-') {
        ++field;
    }
    if (*field == '0' && *(field + 1) == 'x') {
        return true;
    }
    return false;
}

bool FieldList::isFieldReg(size_t whichField) {
    return false;
}
