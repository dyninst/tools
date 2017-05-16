
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
    /*
   bool retval =  (
      !strcmp(token, "llvm_decoding_error")  ||
      !strcmp(token, "empty_decoding")  ||
      !strcmp(token, "decoding_error")  ||
      !strcmp(token, "no_entry")        ||
      !strcmp(token, "No_Entry")        ||
      !strcmp(token, "<invalid_reg>")   ||
      !strcmp(token, "<INVALID_REG>")   ||
      !strcmp(token, "nop")             ||
      !strcmp(token, "bad")             ||
      !strcmp(token, "?")               ||
      !strcmp(token, "undefined")       ||
      !strcmp(token, "nyi")             ||
      !strcmp(token, "invalid")         ||
      !strcmp(token, ".long")           ||
      !strcmp(token, "long")            ||
      !strcmp(token, ".byte")           ||
      !strcmp(token, "%?")              ||
      !strcmp(token, "would_sig")
   );
   return retval;
   */
}

char negHex(char h) {
   
   if (h >= '0' && h <= '5') {
      return 'f' + '0' - h;
   }

   if (h >= '6' && h <= '9') {
      return '9' + '6' - h;
   }

   if (h >= 'a' && h <= 'f') {
      return 'f' + '0' - h;
   }

   return h;
}

bool isHex(char c) {
   return ((c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f'));
}

bool startHex(char* str) {
   return (*(str - 1) == '0' && *str == 'x');
}

void strStripDigits(char* str) {
   std::string validStartChars = " (){}[]#$*+:";
   std::string validEndChars = " ()[]{},*";
   char* place = str;
   char* cur = str;
   while (*cur) {
      if (isdigit(*cur) || *cur == '-') {
         char* endNum = NULL;
         strtod(cur, &endNum);
         if ((!*endNum || validEndChars.find(*endNum) != std::string::npos) && 
                (cur == str || 
                validStartChars.find(*(cur - 1)) != std::string::npos)) {

            *place = '_';
            place++;
            cur = endNum;
         }
      }
      if (*cur) {
         *place = *cur;
         place++;
         cur++;
      }
   }
   *place = '\0';
}

void strStripHex(char* buf) {
    char* str = buf;
    char* newStr = str;
   
    /* We'll be skipping over copying hex characters. */
    bool inHex = false;
    while (*str) {

       /* If we're in hex, just make sure we haven't hit non-hex characters. */
       if (inHex) {
          if (!isHex(*str)) {
             inHex = false;
          }
       }

       /* If we aren't in hex, or we hit a non-hex character, assess whether or
        * not we are starting a new hex string.*/
       if (!inHex) {

           /* Negative hex strings will begin with a '-', followed by 0x */
           if (!strncmp(str, "-0x", 3)) {

               /* We use "0x" to denote that a hex value was found here, so 
                * copy that into place over the "-0x". */
               strncpy(newStr, "0x", 2);
               newStr += 2;
               str += 2;
               inHex = true;
           } else {

               /* The current character isn't a part of a hex string, so copy 
                *it. */
               *newStr = *str;
               newStr++;
            
               /* If we aren't at a "-0x" string, check if we're entering a hex
                * string by seeing if we're at the 'x' in "0x". */
               if (str != buf) {
                   inHex = startHex(str);
               }
           }
        }

        str++;
    }
    *newStr = 0;
}

void printBufferBits(char* buf, int len) {
   int i, j;
   for (i = 0; i < len; i++) {
      for (j = 0; j < 8; j++) {
         if ((buf[i] >> j) & 1) {
            printf("1");
         } else {
            printf("0");
         }
      }
   }
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

void randomizeBufferBitVector(char* buf, unsigned int* pos, unsigned int len) {
   char* randBuf = (char*)malloc(len);
   randomizeBuffer(randBuf, len);
   setBufferBitVector(buf, pos, randBuf, len);
   free(randBuf);
}

void setBufferBitVector(char* buf, 
                        unsigned int* pos, 
                        char* value, 
                        unsigned int len) {
   for (unsigned int i = 0; i < len; i++) {
      setBufferBit(buf, pos[i], getBufferBit(value, i));
   }
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
