
#include <iostream>
#include <string.h>
#include "Normalization.h"

static FindList* initUnused64BitSegRegsFindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, "%es:", "");
    addReplaceTerm(*fl, "%cs:", "");
    addReplaceTerm(*fl, "%ds:", "");
    addReplaceTerm(*fl, "%ss:", "");
    return fl;
}

void removeUnused64BitSegRegs(char* buf, int bufLen) {
    static FindList* fl = initUnused64BitSegRegsFindList();
    fl->process(buf, bufLen);
}

void addImpliedX86Index(char* buf, int bufLen) {
    char* cur = buf;
    bool inParens = false;
    int nCommas = 0;
    while (*cur) {
        if (*cur == '(') {
            inParens = true;
            nCommas = 0;
        } else if (*cur == ',') {
            ++nCommas;
        } else if (*cur == ')') {
            if (inParens && nCommas == 1) {
                char temp[bufLen];
                strcpy(temp, cur);
                snprintf(cur, bufLen - (cur - buf), ", 1%s", temp);
            }
            inParens = false;
            return;
        }
        ++cur;
    }
}

void removeImplicitST0(char* buf, int bufLen) {
    
    std::string str = std::string(buf);
    
    if (*buf != 'f' && str.find(" f") == std::string::npos) {
        return;
    }

    removeOperand(str, "fadd", ", %st(0)");
    removeOperand(str, "fld", ", %st(0)");
    removeOperand(str, "fbld", ", %st(0)");
    removeOperand(str, "fst", "%st(0), ");
    removeOperand(str, "fbstp", "%st(0), ");
    removeOperand(str, "fstpq", "%st(0), ");
    //removeOperand(str, "fcmov", ", %st(0)"); // x
    removeOperand(str, "fild", ", %st(0)");
    removeOperand(str, "fcomp", "%st(0), ");
    removeOperand(str, "fist", "%st(0), ");
    removeOperand(str, "fistp", "%st(0), ");
    removeOperand(str, "fst", "%st(0), ");
    removeOperand(str, "fstp", "%st(0), ");
    removeOperand(str, "fstpnce", "%st(0), ");
    removeOperand(str, "fisub", ", %st(0)");
    removeOperand(str, "fsub", ", %st(0)");
 
    removeOperand(str, "fmul", ", %st(0)");
    removeOperand(str, "fucom", ", %st(0)");
    removeOperand(str, "fcom", ", %st(0)");
    removeOperand(str, "fidiv", ", %st(0)");
    removeOperand(str, "fidivr", ", %st(0)");
    removeOperand(str, "ficomp", ", %st(0)");
    removeOperand(str, "fdiv", ", %st(0)");
    removeOperand(str, "fimul", ", %st(0)");
    removeOperand(str, "fiadd", ", %st(0)");
 
    removeOperand(str, "ficom", ", %st(0)");
    removeOperand(str, "fsubrl", "%st(0), ");
    removeOperand(str, "fbstp", "%st(0), ");
    removeOperand(str, "fsqrt", " %st(0)");
    removeOperand(str, "fxch", ", %st(0)");
    removeOperand(str, "fptan", ", %st(0)");
 
    removeOperand(str, "fyl2x", "%st(1), %st(0)");
    removeOperand(str, "fprem1", "%st(1), %st(0)");
    removeOperand(str, "fprem", "%st(1), %st(0)");
    removeOperand(str, "fscale", "%st(1), %st(0)");
    removeOperand(str, "fxtract", "%st(1), %st(0)");
    removeOperand(str, "fpatan", "%st(1), %st(0)");
    removeOperand(str, "fsincos", "%st(1), %st(0)");
    removeOperand(str, "f2xm1", "%st(0)");
    removeOperand(str, "fchs", "%st(0)");
    removeOperand(str, "fldz", "%st(0)");
    removeOperand(str, "fldpi", "%st(0)");
    removeOperand(str, "ftst", "%st(0)");
    removeOperand(str, "fcompp", "%st(1)");
    removeOperand(str, "fucompp", "%st(1)");
    removeOperand(str, "fptan", "%st(1)");
    removeOperand(str, "fld1", "%st(0)");
    removeOperand(str, "fsin", "%st(0)");
    
    strncpy(buf, str.c_str(), bufLen);
    if (buf[str.length() - 1] == ' ') {
       buf[str.length() - 1] = 0;
    }
}

FindList* initRemoveImplicitK0FindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, "{%k0}", "");
    return fl;
}

void removeImplicitK0(char* buf, int bufLen) {
    static FindList* fl = initRemoveImplicitK0FindList();
    fl->process(buf, bufLen);
}

FindList* initRemoveHintsFindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, "hint-taken", "");
    addReplaceTerm(*fl, "hint-not-taken", "");
    addReplaceTerm(*fl, "xacquire", "");
    addReplaceTerm(*fl, "xrelease", "");
    return fl;
}

void removeX86Hints(char* buf, int bufLen) {
    static FindList* fl = initRemoveHintsFindList();
    fl->process(buf, bufLen);
}

FindList* initOpcodeOnlyMissing0x0FindList() {
    FindList* fl = new FindList(877);
    addAppend0x0IfEndsTerm(*fl, "set");
    addAppend0x0IfEndsTerm(*fl, "add");
    addAppend0x0IfEndsTerm(*fl, "sub");
    addAppend0x0IfEndsTerm(*fl, "mul");
    addAppend0x0IfEndsTerm(*fl, "div");
    addAppend0x0IfEndsTerm(*fl, "cmp");
    addAppend0x0IfEndsTerm(*fl, "fist");
    addAppend0x0IfEndsTerm(*fl, "fcom");
    addAppend0x0IfEndsTerm(*fl, "fild");
    addAppend0x0IfEndsTerm(*fl, "fld");
    addAppend0x0IfEndsTerm(*fl, "fbstp");
    addAppend0x0IfEndsTerm(*fl, "inc");
    addAppend0x0IfEndsTerm(*fl, "dec");
    addAppend0x0IfEndsTerm(*fl, "ltr");
    addAppend0x0IfEndsTerm(*fl, "lidt");
    addAppend0x0IfEndsTerm(*fl, "lgdt");
    addAppend0x0IfEndsTerm(*fl, "sidt");
    addAppend0x0IfEndsTerm(*fl, "sldt");
    addAppend0x0IfEndsTerm(*fl, "lldt");
    addAppend0x0IfEndsTerm(*fl, "sgdt");
    addAppend0x0IfEndsTerm(*fl, "vmptr");
    addAppend0x0IfEndsTerm(*fl, "stor");
    addAppend0x0IfEndsTerm(*fl, "save");
    addAppend0x0IfEndsTerm(*fl, "push");
    addAppend0x0IfEndsTerm(*fl, "pop");
    addAppend0x0IfEndsTerm(*fl, "jmp");
    addAppend0x0IfEndsTerm(*fl, "not");
    addAppend0x0IfEndsTerm(*fl, "neg");
    addAppend0x0IfEndsTerm(*fl, "fst");
    addAppend0x0IfEndsTerm(*fl, "ficom");
    addAppend0x0IfEndsTerm(*fl, "fnst");
    addAppend0x0IfEndsTerm(*fl, "lmsw");
    addAppend0x0IfEndsTerm(*fl, "smsw");
    addAppend0x0IfEndsTerm(*fl, "str");
    addAppend0x0IfEndsTerm(*fl, "vmclear");
    addAppend0x0IfEndsTerm(*fl, "cmpxchg");
    addAppend0x0IfEndsTerm(*fl, "ldmx");
    addAppend0x0IfEndsTerm(*fl, "stmx");
    addAppend0x0IfEndsTerm(*fl, "ver");
    addAppend0x0IfEndsTerm(*fl, "fbld");
    addAppend0x0IfEndsTerm(*fl, "invlpg");
    return fl;
}

FindList* initMissing0x0FindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, " , ", " 0x0, ");
    addReplaceTerm(*fl, "s:, ", "s:0x0, ");
    addReplaceTerm(*fl, "s:{", "s:0x0{");
    addReplaceTerm(*fl, " {1to", " 0x0{1to");
    return fl;
}

void addMissing0x0(char* buf, int bufLen) {
    static FindList* fl = initMissing0x0FindList();
    static FindList* opcodeOnlyFl = initOpcodeOnlyMissing0x0FindList();
    fl->process(buf, bufLen);
    char* cur = buf;
    if (strncmp(buf, "xlat", 4) && strncmp(buf, "out", 4) && strncmp(buf, "mask", 4)) {
        while (*cur) {
            ++cur;
        }
        --cur;
        if (*cur == ':') {
            strcpy(cur + 1, "0x0");
        } else if (*cur == ',') {
            strcpy(cur + 1, " 0x0");
        }
    }
    bool foundSpace = false;
    cur = buf;
    while (*cur && !foundSpace) {
        if (*cur == ' ') {
            foundSpace = true;
        }
        ++cur;
    }
    if (!foundSpace) {
        if (strcmp(buf, "fsincos") &&
            strcmp(buf, "fdecstp") &&
            strcmp(buf, "fincstp") &&
            strcmp(buf, "fldpi")) {
            opcodeOnlyFl->process(buf, bufLen);
        }
    }
}

void removeUnusedOverridePrefixes(char* buf, int bufLen) {
    std::string result(buf);
   
    removeAtSubStr(result, "data16", 7);
    removeAtSubStr(result, "data16", 7);
    removeAtSubStr(result, "addr32", 7);
    removeAtSubStr(result, "addr32", 7);
    removeAtSubStr(result, "addr16", 7);
    removeAtSubStr(result, "addr16", 7);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
    
}

void signOperands(char* buf, int bufLen, void* arg) {
    char* cur = buf;
    char* place;
    while (*cur) {
        if (*cur == '0' && *(cur + 1) == 'x') {
            place = cur;
            cur += 2;
            while (isxdigit(*cur)) {
                ++cur;
            }
            long long disp = strtoll(place, NULL, 16);
            int intDisp = (int)strtol(place, NULL, 16);
            if ((*cur == ',' || *cur == '\0' || *cur == '{') && (cur == place + 18 && disp < 0)) {
                disp = disp * -1;
                char temp[bufLen - (cur - buf)];
                strcpy(temp, cur);
                snprintf(place, bufLen - (place - buf), "-0x%x%s", (int)disp, temp);
            } else if ((*cur == ',' || *cur == '\0' || *cur == '{') && (cur == place + 10 && intDisp < 0)) {
                intDisp = intDisp * -1;
                char temp[bufLen - (cur - buf)];
                strcpy(temp, cur);
                snprintf(place, bufLen - (place - buf), "-0x%x%s", intDisp, temp);
            }
        }
        ++cur;
    }
}

FindList* initFixCallFindList() {
    FindList* fl = new FindList(877);
    addReplaceTerm(*fl, "ljmpq", "ljmp");
    addReplaceTerm(*fl, "lcallq", "lcall");
    addReplaceTerm(*fl, "lgsq", "lgs");
    addReplaceTerm(*fl, "lfsq", "lgs");
    addReplaceTerm(*fl, "lssq", "lss");
    addReplaceTerm(*fl, "sldtq", "sldt");
    addReplaceTerm(*fl, "sysexitl", "sysexit");
    return fl;
}

void fixCallSuffix(char* buf, int bufLen) {
    static FindList* fl = initFixCallFindList();
    fl->process(buf, bufLen);
}

FindList* initSignedOperandFindList() {
    FindList* fl = new FindList(877);
    fl->addTerm(" dec", &signOperands, NULL);
    fl->addTerm(" inc", &signOperands, NULL);
    fl->addTerm(" test", &signOperands, NULL);
    fl->addTerm(" lsl", &signOperands, NULL);
    fl->addTerm(" sqrt", &signOperands, NULL);
    fl->addTerm(" imul", &signOperands, NULL);
    fl->addTerm(" sms", &signOperands, NULL);
    fl->addTerm(" bts", &signOperands, NULL);
    fl->addTerm(" push", &signOperands, NULL);
    fl->addTerm(" str", &signOperands, NULL);
    fl->addTerm(" sbb", &signOperands, NULL);
    fl->addTerm(" or", &signOperands, NULL);
    fl->addTerm(" cmp", &signOperands, NULL);
    fl->addTerm(" xor", &signOperands, NULL);
    fl->addTerm(" and", &signOperands, NULL);
    fl->addTerm(" sub", &signOperands, NULL);
    fl->addTerm(" add", &signOperands, NULL);
    fl->addTerm(" idiv", &signOperands, NULL);
    fl->addTerm(" imul", &signOperands, NULL);
    fl->addTerm(" shr", &signOperands, NULL);
    fl->addTerm(" adc", &signOperands, NULL);
    fl->addTerm(" xchg", &signOperands, NULL);
    fl->addTerm(" vpunpck", &signOperands, NULL);
    fl->addTerm(" vpack", &signOperands, NULL);
    fl->addTerm(" vpavg", &signOperands, NULL);
    fl->addTerm(" vpadd", &signOperands, NULL);
    fl->addTerm(" vpsub", &signOperands, NULL);
    fl->addTerm(" vpsra", &signOperands, NULL);
    fl->addTerm(" vpmin", &signOperands, NULL);
    fl->addTerm(" vpmax", &signOperands, NULL);
    fl->addTerm(" vpcmp", &signOperands, NULL);
    fl->addTerm("fcomp", &signOperands, NULL);
    fl->addTerm("vor", &signOperands, NULL);
    fl->addTerm("vhadd", &signOperands, NULL);
    fl->addTerm("vsub", &signOperands, NULL);
    fl->addTerm("vand", &signOperands, NULL);
    fl->addTerm("vmax", &signOperands, NULL);
    fl->addTerm("vmin", &signOperands, NULL);
    fl->addTerm("vunpck", &signOperands, NULL);
    fl->addTerm("vreduce", &signOperands, NULL);
    fl->addTerm("vpmul", &signOperands, NULL);
    fl->addTerm("vpsrl", &signOperands, NULL);
    fl->addTerm("vpsll", &signOperands, NULL);
    fl->addTerm("ficomp", &signOperands, NULL);
    fl->addTerm("rorb", &signOperands, NULL);
    fl->addTerm("coms", &signOperands, NULL);
    fl->addTerm("rorb", &signOperands, NULL);
    return fl;
}

void signedOperands(char* buf, int bufLen) {
    static FindList* fl = initSignedOperandFindList();
    /*fl->process(buf, bufLen);
   
    if (strncmp(buf, "idiv", 4) &&
        strncmp(buf, "imul", 4) &&
        strncmp(buf, "shr", 3) &&
        strncmp(buf, "adc", 3) &&
        strncmp(buf, "xchg", 4) &&
        strncmp(buf, "vpunpck", 7) &&
        strncmp(buf, "vpack", 5) &&
        strncmp(buf, "vpavg", 5) &&
        strncmp(buf, "vpadd", 5) &&
        strncmp(buf, "vpsub", 5) &&
        strncmp(buf, "vpmin", 5) &&
        strncmp(buf, "vpmax", 5) &&
        strncmp(buf, "vpcmp", 5) &&
        strncmp(buf, "vpsra", 5) &&
        strncmp(buf, "dec", 3) &&
        strncmp(buf, "inc", 3) &&
        strncmp(buf, "test", 4) &&
        strncmp(buf, "push", 4) &&
        strncmp(buf, "bts", 3) &&
        strncmp(buf, "sms", 3) &&
        strncmp(buf, "imul", 4) &&
        strncmp(buf, "sqrt", 4) &&
        strncmp(buf, "lsl", 3) &&
        strncmp(buf, "str", 3) &&
        strncmp(buf, "sbb", 3) &&
        strncmp(buf, "or", 2) &&
        strncmp(buf, "cmp", 3) &&
        strncmp(buf, "xor", 3) &&
        strncmp(buf, "and", 3) &&
        strncmp(buf, "sub", 3) &&
        strncmp(buf, "add", 3)) {
        return;
    }*/

    signOperands(buf, bufLen, NULL);
}

void removeUnusedRepPrefixes(char* buf, int bufLen) {
    std::string result(buf);
   
    if (!strncmp(buf, "ins", 3) ||
        !strncmp(buf, "outs", 4) ||
        !strncmp(buf, "lods", 4) ||
        !strncmp(buf, "stos", 4) ||
        !strncmp(buf, "cmps", 4) ||
        !strncmp(buf, "scas", 4) ||
        !strncmp(buf, "movs", 4) ||
        result.find(" ins") != std::string::npos ||
        result.find(" outs") != std::string::npos ||
        result.find(" lods") != std::string::npos ||
        result.find(" stos") != std::string::npos ||
        result.find(" cmps") != std::string::npos ||
        result.find(" scas") != std::string::npos ||
        result.find(" movs") != std::string::npos) {
        return;
    }

    removeAtSubStr(result, "repne", 6);
    removeAtSubStr(result, "repne", 6);
    removeAtSubStr(result, "repnz", 6);
    removeAtSubStr(result, "repnz", 6);
    removeAtSubStr(result, "repz", 5);
    removeAtSubStr(result, "repz", 5);
    removeAtSubStr(result, "rep", 4);
    removeAtSubStr(result, "rep", 4);
    
    strncpy(buf, result.c_str(), bufLen);
    buf[bufLen - 1] = 0;
    
}

void fixStRegs(char* buf, int bufLen) {
    char tmpBuf[bufLen];
    char* place = &tmpBuf[0];
    char* cur = buf;
    char* firstRegStart = NULL;
    while (*cur && place + 5 < &tmpBuf[bufLen - 1]) {
        if (!strncmp(cur, "%st", 3)) {
            if (firstRegStart == NULL) {
                firstRegStart = cur;
            }
            for (int i = 0; i < 3; i++) {
                *place = *cur;
                place++;
                cur++;
            }
            *place = '(';
            place++;
            *place = *cur;
            place++;
            *place = ')';
            place++;
        } else if (firstRegStart != NULL) {
            *place = *cur;
            place++;
        }
        cur++;
    }
    *place = '\0';
    if (firstRegStart != NULL) {
        strncpy(firstRegStart, &tmpBuf[0], bufLen + buf - firstRegStart);
    }
}


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

void convertToDec(char* buf, int bufLen) {
    char tmpBuf[bufLen];
    char* end; 
    long long int val = strtoll(buf, &end, 16);
    snprintf(&tmpBuf[0], bufLen, "%lld%s", val, end);
    strncpy(buf, &tmpBuf[0], bufLen);
}

void hexToDecConstants(char* buf, int bufLen) {
   char* cur = buf;
   while (*cur) {
        if (!strncmp(cur, "0x", 2)) {
            convertToDec(cur, bufLen - (cur - buf));
        }
        ++cur;
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
   bool inParens = false;

   while (*cur) {
        while (*cur && (isspace(*cur) || *cur == '(' || *cur == '$')) {
            if (*cur == '(') {
                inParens = true;
            }
            ++cur;
        }

        if (*cur == '-') {
            ++cur;
        }

        if (!inParens &&
            (*cur != '0' || *(cur + 1) != 'x') && 
            (isdigit(*cur) || *(cur) == '-')) {
            
            convertToHex(cur, buf + bufLen - cur);
        }

        while (*cur && (!isspace(*cur) && *cur != '(')) {
            if (*cur == ')') {
                inParens = false;
            }
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

void removePoundComment(char* buf, int bufLen) {
    char* cur = buf;
    while (*cur && *cur != '#') {
        ++cur;
    }
    if (*cur == '#') {
        *cur = '\0';
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

void addOperandSwapTerm(FindList& fl, const char* opcode, size_t pos1, size_t pos2) {
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

void addAppend0x0IfEndsTerm(FindList& fl, const char* str) {
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

void addRemoveLastLetterTerm(FindList& fl, const char* str) {
    fl.addTerm(str, &flRemoveLastLetterFunc, NULL);
}

void addReplaceTerm(FindList& fl, const char* oldStr, const char* newStr) {
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

void cleanX86NOP(char* buf, int bufLen) {
    if (strncmp(buf, "nop", 3) == 0) {
        *(buf + 3) = '\0';
    }
}
