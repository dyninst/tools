
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
    if (as == NULL) {
        std::cerr << "Must specify assembler with \"-as=\"\n";
        exit(-1);
    }
    static const char* asOpts = Options::get("-asopt=");
    static char** asArgv = makeAsArgs(as, asOpts, tmpname);

    char arrBuf[REASM_BUF_LEN];
    char* buf = &arrBuf[0];

    snprintf(buf, REASM_BUF_LEN, ".global main\n\nmain:\n\t%s", str);
    writeStrToFile(tmpname, 0, buf);
   
    int p[2];
    pipe(p);
    int status;

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid > 0) {
        close(p[1]);
        char c;
        int assemblerErrorTabCount = 5;
        std::cout << "STDERR: ";
        int tabCount = 0;
        while (read(p[0], &c, 1) > 0) {
            if (tabCount >= assemblerErrorTabCount) {
                std::cout << c;
            }
            if (c == ':') {
                tabCount++;
            }
        }
        std::cout << "\n";
        waitpid(pid, &status, 0);
    } else {
        close(p[0]);
        dup2(p[1], STDERR_FILENO);
        close(p[1]);
        char* envp = NULL;
        execve(asArgv[0], asArgv, &envp);
        std::cout << strerror(errno) << "\n";
        assert(false && "execve() should never return");
    }

    close(p[0]);


    if (status != 0) {
        return 'E';
    }

    *outputLen = readReassembledBytes(tmpname, byteBuf, bufLen);
    if (*outputLen > nBytes || memcmp(byteBuf, bytes, *outputLen)) {
        return 'D';
    }
    return 'S';
}

char** makeObjdumpArgs(const char* objdump, const char* tmpname) {

    const int nNeededArgs = 4;
    
    char** result = (char**)malloc(sizeof(*result) * (nNeededArgs));
    assert(result != NULL);

    int tempnameLen = strlen(tmpname);
    int inputFilenameLen = tempnameLen + strlen(".o") + 1;
    
    result[0] = strdup(objdump);
    result[1] = strdup("-d");
    result[2] = (char*)malloc(inputFilenameLen);
    assert(result[2] != NULL);
    snprintf(result[2], inputFilenameLen, "%s.o", tmpname);

    result[nNeededArgs - 1] = NULL;
    return result;
}

int readReassembledBytes(const char* filename, char* outBytes, int bufLen) {
   
    static const char* objdump = Options::get("-objdump=");
    if (objdump == NULL) {
        std::cerr << "Must specify objdump with \"-objdump=\"\n";
        exit(-1);
    }
    static char** objdumpArgv = makeObjdumpArgs(objdump, filename);
    
    char buf[REASM_BUF_LEN];
    char* str = &buf[0];
    int status;

    snprintf(str, REASM_BUF_LEN, "%s.dmp", filename);
    
    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid > 0) {
        waitpid(pid, &status, 0);
    } else {
        char* envp = NULL;
        FILE* outfile = fopen(str, "w+");
        dup2(fileno(outfile), STDOUT_FILENO);
        fclose(outfile);
        execve(objdumpArgv[0], objdumpArgv, &envp);
        std::cout << strerror(errno) << "\n";
        assert(false && "execve() should never return");
    }

    assert(status == 0);

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

