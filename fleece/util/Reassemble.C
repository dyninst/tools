
#include "Reassemble.h"

char reassemble(const char* bytes, int nBytes, const char* str, FILE* tmp, 
        const char* tmpname, char* byteBuf, int bufLen, int* outputLen) {

    static const char* as = Options::get("-as=");
    static const char* asOpts = Options::get("-asopt=");
    if (as == NULL) {
        std::cerr << "Must specify assembler with \"-as=\"\n";
        exit(-1);
    }

    char arrBuf[REASM_BUF_LEN];
    char* buf = &arrBuf[0];

    snprintf(buf, REASM_BUF_LEN, ".global main\n\nmain:\n\t%s", str);
    writeStrToFile(tmpname, 0, buf);
    if (asOpts == NULL) {
        snprintf(buf, REASM_BUF_LEN,
            "%s -o %s.o %s 2>as.out", as, tmpname, tmpname);
    } else {
        snprintf(buf, REASM_BUF_LEN,
            "%s %s -o %s.o %s 2>as.out", as, asOpts, tmpname, tmpname);
    }
    int rc = system(buf);

    if (rc != 0) {
      return 'E';
    }

    *outputLen = readReassembledBytes(tmpname, byteBuf, bufLen);
    if (*outputLen > nBytes || memcmp(byteBuf, bytes, *outputLen)) {
        return 'D';
    }
    return 'S';
}

int readReassembledBytes(const char* filename, char* outBytes, int bufLen) {
   
    static const char* objdump = Options::get("-objdump=");
    if (objdump == NULL) {
        std::cerr << "Must specify objdump with \"-objdump=\"\n";
        exit(-1);
    }
    
    char buf[REASM_BUF_LEN];
    char* str = &buf[0];
    snprintf(str, REASM_BUF_LEN, "%s -d %s.o > %s.tmp", objdump, filename,
        filename);

    system(str);
    snprintf(str, REASM_BUF_LEN, "%s.tmp", filename);
    FILE* bytef = fopen(str, "r+");
    assert(bytef != NULL);

    int flen = fread(str, 1, REASM_BUF_LEN, bytef);
    assert(flen > 0);

    fclose(bytef);

    char* cur = str;
    char* end = str + flen;

    int colonCount = 0;
    while (cur < end && colonCount < BYTE_COLON_COUNT) {
        if (*cur == ':') {
            colonCount++;
        }
        cur++;
    }
    while (isspace(*cur)) {
        cur++;
    }

    int curByte = 0;
    char* byteStart = cur;
    if (Architecture::name == "aarch64") {
        cur += 6;
    }
    while (cur < end - 1 && curByte < bufLen && cur >= byteStart) {
        char c = (getCharHexVal(*cur) << 4) + getCharHexVal(*(cur + 1));
        outBytes[curByte] = c;
        curByte++;
        if (Architecture::name == "aarch64") {
            cur -= 2;
        } else {
            cur += 3;
            if (isspace(*cur) || curByte % 7 == 0) {
                while (cur < end - 1 && *cur != '\n') {
                    cur++;
                }
                while(cur < end - 1 && *cur != ':') {
                    cur++;
                }
                if (*cur == ':') {
                    cur++;
                }
                while(cur < end - 1 && isspace(*cur)) {
                    cur++;
                }
            }
        }
    }

    return curByte;
}

