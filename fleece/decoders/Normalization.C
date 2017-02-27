
#include <iostream>

#include "Normalization.h"

bool isAarch64SysRegInsn(char* inst, int nBytes, char* buf, int bufLen) {
   
    if (inst[3] == (char)0xD5) {
      
        if ((inst[2] & 0xF0) == (char)0x30 ||
            (inst[2] & 0xF0) == (char)0x10) {
         
            strncpy(buf, "MOVE SYSTEM REGISTER", bufLen);
            buf[bufLen - 1] = 0;
            return true;

        } else if ((inst[2] & 0xF8) == (char)0x00 &&
                   (inst[1] & 0xF0) == (char)0x40 &&
                   (inst[0] & 0x1F) == (char)0x1F) {

            strncpy(buf, "MOVE SYSTEM REGISTER", bufLen);
            buf[bufLen - 1] = 0;
            return true;
      
        }
    }
    return false;
}

void cleanSpaces(char* buf, int bufLen) {

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

void removePounds(char* buf, int bufLen) {

    char* cur = buf;
    char* place = buf;

    while (*cur) {
        if (*cur != '#') {
            *place = *cur;
            place++;
        }
        cur++;
    }
    *place = 0;
}

void toLowerCase(char* buf, int bufLen) {

    char* cur = buf;

    while (*cur) {
        if (isupper(*cur)) {
            *cur += 32;
        }
        cur++;
    }
}

void trimHexZeroes(char* buf, int bufLen) {

   char* cur = buf;
   char* place = buf;

   bool inHexZeroes = false;

   while (*cur) {
      
      if (*cur == 'x' && cur > buf && *(cur - 1) == '0' && *(cur + 1) == '0') {
         inHexZeroes = true;
         *place = *cur;
         place++;
      } else if (!inHexZeroes || *cur != '0') {
         inHexZeroes = false;
         *place = *cur;
         place++;
      } else if (!isxdigit(*(cur + 1))) {
         inHexZeroes = false;
         *place = *cur;
         place++;
      }

      cur++;
   }

   *place = 0;
}

void trimHexFs(char* buf, int bufLen) {

   char* cur = buf;
   char* place = buf;

   bool inHexFs = false;

   while (*cur) {
      
      if (*cur == 'x' && cur > buf && *(cur - 1) == '0' && *(cur + 1) == 'f') {
         inHexFs = true;
         *place = *cur;
         place++;
      } else if (!inHexFs || *cur != 'f') {
         inHexFs = false;
         *place = *cur;
         place++;
      } else {
         char next = *(cur + 1);
         if (next != '8' && next != '9' && next != 'a' && next != 'b' && 
             next != 'c' && next != 'd' && next != 'e' && next != 'f') {
            *place = *cur;
            place++;
            inHexFs = false;
         }
      }

      cur++;
   }

   *place = 0;
}

void commaBeforeSpace(char* buf, int bufLen) {

   char* tmp = (char*)malloc(bufLen);
   assert(tmp != NULL);

   char* cur = buf;
   char* place = tmp;

   while (*cur && place < tmp + bufLen) {
      
      if (*cur == ' ' && cur != buf && *(cur - 1) != ',') {
         *place = ',';
         place++;
      }

      *place = *cur;
      place++;

      cur++;
   }
   *place = 0;

   strncpy(buf, tmp, bufLen);
   free(tmp);

}

void spaceAfterCommas(char* buf, int bufLen) {

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

void removeEmptyParens(char* buf, int bufLen) {
   
    char* cur = buf;
    char* place = buf;
    while (*cur) {
        if (*cur == '(' && *(cur + 1) == ')') {
            cur += 2;
        } else {
            if (cur != place) {
                *place = *cur;
            }
            place++;
            cur++;
        }
    }
    *place = *cur;
}

void removeComments(char* buf, int bufLen) {
   
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

void convertToHex(char* buf, int bufLen) {
    char tmpBuf[bufLen];
    char* end; 
    long long int val = strtoll(buf, &end, 10);
    snprintf(&tmpBuf[0], bufLen, "0x%llx%s", val, end);
    strncpy(buf, &tmpBuf[0], bufLen);
}

void decToHexConstants(char* buf, int bufLen) {
   char* cur = buf;

   while (*cur) {
        while (*cur && (isspace(*cur) || *cur == '(' || *cur == '$')) {
            ++cur;
        }

        if ((*cur != '0' || *(cur + 1) != 'x') && 
            (isdigit(*cur) || *(cur) == '-')) {
            
            convertToHex(cur, buf + bufLen - cur);
        }

        while (*cur && (!isspace(*cur) && *cur != '(')) {
            ++cur;
        }
    }
}

void removeHexBrackets(char* buf, int bufLen) {
   char* cur = buf;
   char* place = buf;

   bool ignoreClosing = false;

   while (*cur) {
      if (*cur == '[' && *(cur + 1) != 'x' && isxdigit(*(cur + 1))) {
         ignoreClosing = true;
      } else if (*cur == ']' && ignoreClosing) {
         ignoreClosing = false;
      } else {
         *place = *cur;
         place++;
      }
      cur++;
   }
   *place = *cur;
}

void removeADRPZeroes(char* buf, int bufLen) {
   if (bufLen > 4 && !strncmp(buf, "adrp", 4)) {
      char* cur = buf;
      
      while (*cur) {
         cur++;
      }

      if (cur > buf + 3) {
         *(cur - 3) = 0;
      }
   }
}

bool isAarch64Reg(char* buf, int bufLen) {
 

   if (bufLen < 2) {
      return false;
   }

   if (*buf != 'd') {
      return false;
   }
   buf++;
   
   if (!isdigit(*buf)) {
      return false;
   }
   buf++;

   if (*buf == 0 || *buf == ' ' || *buf == ',') {
      return true;
   }
   
   if (!isdigit(*buf)) {
      return false;
   }

   buf++;
   return (*buf == 0 || *buf == ' ' || *buf == ',');
}


void place0x(char* buf, int bufLen) {
   
   char* tmp = (char*)malloc(bufLen);

   char* place = tmp;
   char* cur = buf;

   while (*cur) {
      *place = *cur;
      place++;
      if (*cur == ' '          && 
          isxdigit(*(cur + 1)) && 
          *(cur + 2) != 's'    &&
          !isAarch64Reg(cur + 1, buf + bufLen - cur - 1)) {
         
         *place = '0';
         place++;
         *place = 'x';
         place++;
      }
      cur++;
   }
   *place = 0;

   strncpy(buf, tmp, bufLen);
   free(tmp);
}

