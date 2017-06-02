
#include <stdio.h>
#include "Architecture.h"
#include "Normalization.h"

static FindList* initUnused64BitSegRegsFindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "%es:", "");
    Normalization::addReplaceTerm(*fl, "%cs:", "");
    Normalization::addReplaceTerm(*fl, "%ds:", "");
    Normalization::addReplaceTerm(*fl, "%ss:", "");
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

    std::cout << "before: " << buf << "\n";

    std::string str = std::string(buf);
    
    if (*buf != 'f' && str.find(" f") == std::string::npos) {
        std::cout << "no change: " << buf << "\n";
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
    
    std::cout << "after: " << buf << "\n";
}

FindList* initMissing0x0FindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, " , ", " 0x0, ");
    Normalization::addReplaceTerm(*fl, "s:, ", "s:0x0, ");
    Normalization::addReplaceTerm(*fl, "s:{", "s:0x0{");
    Normalization::addReplaceTerm(*fl, " {1to", " 0x0{1to");
    return fl;
}

FindList* initOpcodeOnlyMissing0x0FindList() {
    FindList* fl = new FindList(877);
    Normalization::addAppend0x0IfEndsTerm(*fl, "set");
    Normalization::addAppend0x0IfEndsTerm(*fl, "add");
    Normalization::addAppend0x0IfEndsTerm(*fl, "sub");
    Normalization::addAppend0x0IfEndsTerm(*fl, "mul");
    Normalization::addAppend0x0IfEndsTerm(*fl, "div");
    Normalization::addAppend0x0IfEndsTerm(*fl, "cmp");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fist");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fcom");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fild");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fld");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fbstp");
    Normalization::addAppend0x0IfEndsTerm(*fl, "inc");
    Normalization::addAppend0x0IfEndsTerm(*fl, "dec");
    Normalization::addAppend0x0IfEndsTerm(*fl, "ltr");
    Normalization::addAppend0x0IfEndsTerm(*fl, "lidt");
    Normalization::addAppend0x0IfEndsTerm(*fl, "lgdt");
    Normalization::addAppend0x0IfEndsTerm(*fl, "sidt");
    Normalization::addAppend0x0IfEndsTerm(*fl, "sldt");
    Normalization::addAppend0x0IfEndsTerm(*fl, "lldt");
    Normalization::addAppend0x0IfEndsTerm(*fl, "sgdt");
    Normalization::addAppend0x0IfEndsTerm(*fl, "vmptr");
    Normalization::addAppend0x0IfEndsTerm(*fl, "stor");
    Normalization::addAppend0x0IfEndsTerm(*fl, "save");
    Normalization::addAppend0x0IfEndsTerm(*fl, "push");
    Normalization::addAppend0x0IfEndsTerm(*fl, "pop");
    Normalization::addAppend0x0IfEndsTerm(*fl, "jmp");
    Normalization::addAppend0x0IfEndsTerm(*fl, "not");
    Normalization::addAppend0x0IfEndsTerm(*fl, "neg");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fst");
    Normalization::addAppend0x0IfEndsTerm(*fl, "ficom");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fnst");
    Normalization::addAppend0x0IfEndsTerm(*fl, "lmsw");
    Normalization::addAppend0x0IfEndsTerm(*fl, "smsw");
    Normalization::addAppend0x0IfEndsTerm(*fl, "str");
    Normalization::addAppend0x0IfEndsTerm(*fl, "vmclear");
    Normalization::addAppend0x0IfEndsTerm(*fl, "cmpxchg");
    Normalization::addAppend0x0IfEndsTerm(*fl, "ldmx");
    Normalization::addAppend0x0IfEndsTerm(*fl, "stmx");
    Normalization::addAppend0x0IfEndsTerm(*fl, "ver");
    Normalization::addAppend0x0IfEndsTerm(*fl, "fbld");
    Normalization::addAppend0x0IfEndsTerm(*fl, "invlpg");
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

FindList* initFixAddrInsnFindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "ljmpq", "ljmp");
    Normalization::addReplaceTerm(*fl, "lcallq", "lcall");
    Normalization::addReplaceTerm(*fl, "lgsq", "lgs");
    Normalization::addReplaceTerm(*fl, "lfsq", "lgs");
    Normalization::addReplaceTerm(*fl, "lssq", "lss");
    Normalization::addReplaceTerm(*fl, "sldtq", "sldt");
    Normalization::addReplaceTerm(*fl, "sysexitl", "sysexit");
    return fl;
}

void fixAddrInsnSuffix(char* buf, int bufLen) {
    static FindList* fl = initFixAddrInsnFindList();
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

FindList* initFixStRegsFindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "%st0", "%st(0)");
    Normalization::addReplaceTerm(*fl, "%st1", "%st(1)");
    Normalization::addReplaceTerm(*fl, "%st2", "%st(2)");
    Normalization::addReplaceTerm(*fl, "%st3", "%st(3)");
    Normalization::addReplaceTerm(*fl, "%st4", "%st(4)");
    Normalization::addReplaceTerm(*fl, "%st5", "%st(5)");
    Normalization::addReplaceTerm(*fl, "%st6", "%st(6)");
    Normalization::addReplaceTerm(*fl, "%st7", "%st(7)");
    return fl;
}

void fixStRegs(char* buf, int bufLen) {
    static FindList* fl = initFixStRegsFindList();
    fl->process(buf, bufLen);
}

void cleanX86NOP(char* buf, int bufLen) {
    if (strncmp(buf, "nop", 3) == 0) {
        *(buf + 3) = '\0';
    }
}

FindList* initRemoveHintsFindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "hint-taken", "");
    Normalization::addReplaceTerm(*fl, "hint-not-taken", "");
    Normalization::addReplaceTerm(*fl, "xacquire", "");
    Normalization::addReplaceTerm(*fl, "xrelease", "");
    return fl;
}

void removeX86Hints(char* buf, int bufLen) {
    static FindList* fl = initRemoveHintsFindList();
    fl->process(buf, bufLen);
}

FindList* initMaskNameFindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "rne-sae", "rn-sae");
    return fl;
}

void fixMaskName(char* buf, int bufLen) {
    static FindList* fl = initMaskNameFindList();
    fl->process(buf, bufLen);
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

FindList* initRemoveImplicitK0FindList() {
    FindList* fl = new FindList(877);
    Normalization::addReplaceTerm(*fl, "{%k0}", "");
    return fl;
}

void removeImplicitK0(char* buf, int bufLen) {
    static FindList* fl = initRemoveImplicitK0FindList();
    fl->process(buf, bufLen);
}

void x86_64_norm(char* buf, int bufLen) {
    removeUnused64BitSegRegs(buf, bufLen);
    addImpliedX86Index(buf, bufLen);
    removeImplicitK0(buf, bufLen);
    fixStRegs(buf, bufLen);
    removeImplicitST0(buf, bufLen);
    removeUnusedRepPrefixes(buf, bufLen);
    signedOperands(buf, bufLen);
    fixAddrInsnSuffix(buf, bufLen);
    cleanX86NOP(buf, bufLen);
    removeX86Hints(buf, bufLen);
    addMissing0x0(buf, bufLen);
    fixMaskName(buf, bufLen);
    decToHexConstants(buf, bufLen);
}
