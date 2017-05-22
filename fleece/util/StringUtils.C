
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
#include <unordered_map>
#include "StringUtils.h"

static std::unordered_map<const char*, int, StringUtils::str_hash, StringUtils::str_eq>* initErrorMap() {
    std::unordered_map<const char*, int, StringUtils::str_hash, StringUtils::str_eq>* errMap = 
        new std::unordered_map<const char*, int, StringUtils::str_hash, StringUtils::str_eq>();
    errMap->insert(std::make_pair(strdup("llvm_decoding_error"), 1));
    errMap->insert(std::make_pair(strdup("empty_decoding"), 1));
    errMap->insert(std::make_pair(strdup("decoding_error"), 1));
    errMap->insert(std::make_pair(strdup("no_entry"), 1));
    errMap->insert(std::make_pair(strdup("No_Entry"), 1));
    errMap->insert(std::make_pair(strdup("<invalid_reg>"), 1));
    errMap->insert(std::make_pair(strdup("<INVALID_REG>"), 1)); 
    errMap->insert(std::make_pair(strdup("nop"), 1)); 
    errMap->insert(std::make_pair(strdup("bad"), 1));
    errMap->insert(std::make_pair(strdup("?"), 1));
    errMap->insert(std::make_pair(strdup("%,"), 1));
    errMap->insert(std::make_pair(strdup("%("), 1));
    errMap->insert(std::make_pair(strdup("%{"), 1));
    errMap->insert(std::make_pair(strdup("fixme"), 1));
    errMap->insert(std::make_pair(strdup("undefined"), 1));
    errMap->insert(std::make_pair(strdup("nyi"), 1));
    errMap->insert(std::make_pair(strdup("invalid"), 1));
    errMap->insert(std::make_pair(strdup(".long"), 1));
    errMap->insert(std::make_pair(strdup("long"), 1));
    errMap->insert(std::make_pair(strdup(".byte"), 1));
    errMap->insert(std::make_pair(strdup("%?"), 1)); 
    errMap->insert(std::make_pair(strdup("would_sig"), 1));
    errMap->insert(std::make_pair(strdup("nop/reserved"), 1));
    return errMap;
}

/*
 * This function is used to cross-check the error reporting of multiple
 * decoders. The list below is all tokens which suggest that an error has
 * occured during the decoding process. Every entry is checked for every
 * decoder used during reporting.
 */
bool signalsError(const char* token) {
    
    static std::unordered_map<const char*, int, StringUtils::str_hash, StringUtils::str_eq>* errMap = 
        initErrorMap();
    if (token == NULL || !*token) {
        return false;
    }
    auto err = errMap->find(token);
    if (err != errMap->end()) {
        return true;
    }
    return false;
}

unsigned char getBufferBit(char* buf, int bit) {
   return (buf[bit / 8] & (1 << (7 - bit % 8))) >> (7 - bit % 8);
}

void setBufferBit(char* buf, int bit, int val) {
   if (val & 1) {
      buf[bit / 8] |= 1 << (7 - bit % 8);
   } else {
      buf[bit / 8] &= ~(1 << (7 - bit % 8));
   }
}

void flipBufferBit(char* buf, int bit) {
   buf[bit / 8] ^= 1 << (7 - bit % 8);
}

int randomizeBuffer(char* buf, unsigned int len) {
   char* ptr = buf;
   for (ptr = buf; ptr < buf + len; ptr++) {
      *ptr = (char)(rand() & 0xFF);
   }
   return 0;
}

void removeOperand(std::string& str, const std::string& op, const std::string& operand) {
   if (str.find(op) != std::string::npos) {
      size_t pos = str.find(operand);
      if (pos != std::string::npos) {
         str.erase(pos, operand.length());
         if (pos < str.length() && str.at(pos) == ',') {
            str.erase(pos, 2);
         }
      }
   }
}

void removeAtSubStr(std::string& str, const std::string& substr, int len) {
   size_t index = str.find(substr);
   if (index != std::string::npos) {
      str = str.erase(index, len);
   }
}
void removeCharacter(char* buf, int bufLen, char c) {
   char* place = buf;
   char* cur = buf;
   
   while (*cur) {
      if (*cur != c) {
         *place = *cur;
         place++;
      }
      cur++;
   }
   *place = 0;
}

std::string asmErrorToFilename(const char* asmError) {
    std::string endChars = "[]{}\\/;:`'\"\n()";
    int nameLen = strlen(asmError) + 1;
    if (nameLen > MAX_ERROR_FILENAME_LENGTH) {
        nameLen = MAX_ERROR_FILENAME_LENGTH;
    }
    char buf[nameLen];
    char* place = &buf[0];
    const char* endPtr = place + nameLen;
    const char* cur = asmError;
    while (isspace(*cur)) {
        cur++;
    }
    bool done = false;
    while (!done && *cur && place < endPtr) {

        if (*cur == '`' || *cur == '\'') {
            
            ++cur;
            while (*cur && *cur != '\'' && *cur != '`') {
                ++cur;
            }
            if (*cur == '\'') {
                ++cur;
            }
            if (isspace(*cur)) {
                ++cur;
            }
        }

        if (*cur == '0' && *(cur + 1) == 'x') {
            while(*cur && !isspace(*cur)) {
                ++cur;
            }
        }

        if (*cur && endChars.find(*cur) == std::string::npos) {
            if (isspace(*cur)) { 
                *place = '_';
            } else {
                *place = *cur;
            }
            ++place;
        } else {
            *place = '\0';
            if (place > &buf[0] && *(place - 1) == '_') {
                *(place - 1) = '\0';
            }
            done = true;
        }
        ++cur;
    }
    *place = '\0';

    if (*buf == '\0') {
        return std::string("no_message");
    }

    return std::string(buf);
}

void printByteBuffer(std::ostream& stream, const char* bytes, int nBytes) {
    stream << std::hex << std::setfill('0') << std::setw(2);
    for (int j = 0; j < nBytes; j++) {
        stream << (unsigned int)(unsigned char)bytes[j];
        if (j < nBytes - 1) {
            stream << " ";
        }
    }
    stream << std::dec;
}
