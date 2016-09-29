
#include "Reassemble.h"

int getOptArgCount(const char* opts) {
    
    if (opts == NULL)
        return 0;

    int optArgCount = 1;
    while(*opts) {
        if (*opts == ',')
            optArgCount++;
        opts++;
    }
    
    return optArgCount;
}

void fillOptArgs(char** args, const char* opts) {
    const char* argStart = opts;
    const char* argEnd = opts;
    int curArg = 0;
    while (*argEnd) {
        if (*argEnd == ',') {
            args[curArg] = strndup(argStart, argEnd - argStart);
            argStart = argEnd + 1;
            curArg++;
        }
        argEnd++;
    }
    args[curArg] = strdup(argStart);
}

char** makeAsArgs(const char* as, const char* asOpts, 
        const char* tmpname) {

    const int nNeededArgs = 5;
    int nOptArgs = getOptArgCount(asOpts);
    
    char** result = (char**)malloc(sizeof(*result)*(nOptArgs + nNeededArgs));
    assert(result != NULL);

    result[0] = strdup(as);
    result[1] = strdup(tmpname);
    result[2] = strdup("-o");
    int outputFilenameLen = strlen(tmpname) + strlen(".o") + 1;
    result[3] = (char*)malloc(outputFilenameLen);
    assert(result[3] != NULL);
    snprintf(result[3], outputFilenameLen, "%s.o", tmpname);

    if (nOptArgs > 0) {
        fillOptArgs(&result[4], asOpts);
    }

    result[nOptArgs + nNeededArgs - 1] = NULL;
    return result;
}

char reassemble(const char* bytes, int nBytes, const char* str, FILE* tmp, 
        const char* tmpname, char* byteBuf, int bufLen, int* outputLen) {

    static const char* as = Options::get("-as=");
    static const char* asOpts = Options::get("-asopt=");
    static char** asArgv = makeAsArgs(as, asOpts, tmpname);
    if (as == NULL) {
        std::cerr << "Must specify assembler with \"-as=\"\n";
        exit(-1);
    }

    char arrBuf[REASM_BUF_LEN];
    char* buf = &arrBuf[0];

    snprintf(buf, REASM_BUF_LEN, ".global main\n\nmain:\n\t%s", str);
    writeStrToFile(tmpname, 0, buf);
    
    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (status != 0) {
            return 'E';
        }
    } else {
        char* envp = NULL;
        execve(asArgv[0], asArgv, &envp);
        std::cout << strerror(errno) << "\n";
        assert(false && "execve() should never return");
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

