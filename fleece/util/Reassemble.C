
#include "Reassemble.h"

char reassemble(const char* bytes, int nBytes, const char* str, FILE* tmp, const char* tmpname) {

    char arrBuf[BUFFER_SIZE];
    char* buf = &arrBuf[0];

    snprintf(buf, BUFFER_SIZE, ".global main\n\nmain:\n\t%s", str);
    writeStrToFile(tmpname, 0, buf);
    snprintf(buf, BUFFER_SIZE, "as -o %s.o %s 2>as.out", tmpname, tmpname);
    int rc = system(buf);

    if (rc != 0) {
      return 'E';
    }

    snprintf(buf, BUFFER_SIZE, "objdump -d %s.o > %s.tmp", tmpname, tmpname);
    system(buf);

    snprintf(buf, BUFFER_SIZE, "%s.tmp", tmpname);
    FILE* bytef = fopen(buf, "r+");
    assert(bytef != NULL);

    int flen = fread(buf, 1, BUFFER_SIZE, bytef);
    assert(flen > 0);

    fclose(bytef);

    char* cur = buf;
    char* end = buf + flen;

    int tabCount = 0;
    while (cur < end && tabCount < GOAL_TAB_COUNT) {
        if (*cur == '\t') {
            tabCount++;
        }
        cur++;
    }

    int curByte = 0;
    char* byteStart = cur;
    while (!isspace(*cur) && cur < end - 1 && curByte < nBytes) {
        char c = (getCharHexVal(*cur) << 4) + getCharHexVal(*(cur + 1));
        if (c != bytes[curByte]) {
            return 'D';
        }
        curByte++;
        cur += 3;
    }

    if (cur >= end - 1 && curByte != nBytes) {
        return 'D';
    }

    return 'S';
}

