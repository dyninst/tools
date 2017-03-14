
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
    static std::string separators = " ,\t[]{}():$#*+-\n";
    return separators.find(c) != std::string::npos;
}

size_t FieldList::detectNumFields(const char* buf) {
    size_t nFields = 0;
    
    // The string does not start in a field if the first character is a separator.
    bool inField = !isSeparator(*buf);
    
    // Iterate over the string counting the number of fields with at least one separator between 
    // each.
    while (*buf) {
        if (isSeparator(*buf)) {
            if (inField) {
                ++nFields;
            }
            inField = false;
        } else {
            inField = true;
        }
        ++buf;
    }
   
    // If we ended without a space and hit at least one non-space character, then we need to count
    // the last field as well.
    if (inField) {
        ++nFields;
    }

    return nFields;
}

void FieldList::allocateFieldsAndSeparators() {
    fields = new char*[nFields];
    separators = new char*[nFields + 1];
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
    char* lastSepChar;

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
        separators[nFields] = new char[1];
        assert(separators[nFields] != NULL);
        separators[nFields][0] = '\0';
    } else {
        int len = cur - strStart;
        char* newStr = new char[len + 1];
        strncpy(newStr, strStart, len);
        newStr[len] = '\0';
        separators[curField] = newStr;
    }

    //std::cout << "Field list from: " << buf << "\n";
    //print(stdout);
}

FieldList::FieldList(const char* buf) {
    nFields = detectNumFields(buf);
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
