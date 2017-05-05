
#include "Reassemble.h"
#include <iostream>
#include <iomanip>
#include <libelf.h>
#include <err.h>
#include <fcntl.h>
#include <spawn.h>

#define REASM_CACHE_SIZE 5

unsigned long long totalReasmTime = 0;
unsigned long long numReassembled = 0;
unsigned long long numReasmCacheHits = 0;
std::vector<char*> reasmCachedInsns;
std::vector<int> reasmCachedNBytes;
std::vector<char*> reasmCachedBytes;
std::vector<char> reasmCachedResults;
std::vector<char*> reasmCachedErrors;
size_t currentReasmCacheLine = 0;

// This default value can be overriden by the "-asf=" option.
const char* REASM_FILENAME = "/tmp/tmp.s";

void initReassembly() {
    const char* reasmFilename = Options::get("-asf=");
    if (reasmFilename != NULL) {
        REASM_FILENAME = reasmFilename;
    }
}

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

    const int nNeededArgs = 4/*5*/;
    int nOptArgs = getOptArgCount(asOpts);
    
    char** result = (char**)malloc(sizeof(*result)*(nOptArgs + nNeededArgs));
    assert(result != NULL);

    result[0] = strdup(as);
    //result[1] = strdup("\"\"");
    result[1/*2*/] = strdup("-o");
    int outputFilenameLen = strlen(tmpname) + strlen(".o") + 1;
    result[2/*3*/] = (char*)malloc(outputFilenameLen);
    assert(result[2/*3*/] != NULL);
    snprintf(result[2/*3*/], outputFilenameLen, "%s.o", tmpname);

    if (nOptArgs > 0) {
        fillOptArgs(&result[3/*4*/], asOpts);
    }

    result[nOptArgs + nNeededArgs - 1] = NULL;
    return result;
}

bool cacheFillResults(const char* str, char* byteBuf, int bufLen, int* outputLen,
        char* errorBuf, int errorBufLen, char* reasmResult) {

    for (size_t i = 0; i < reasmCachedInsns.size(); ++i) {
        if (!strcmp(reasmCachedInsns[i], str)) {
            *reasmResult = reasmCachedResults[i];
            *outputLen = reasmCachedNBytes[i];
            if (reasmCachedNBytes[i] > bufLen) {
                std::cerr << "ERROR: reassembly buffer too small\n";
                exit(-1);
            }
            memcpy(byteBuf, reasmCachedBytes[i], reasmCachedNBytes[i]);
            strncpy(errorBuf, reasmCachedErrors[i], errorBufLen);
            return true;
        }
    }
    return false;
}


void cacheAddResults(const char* str, char* byteBuf, int bufLen, int* outputLen,
        char* errorBuf, int errorBufLen, char reasmResult) {

    size_t index = currentReasmCacheLine;
    if (index < reasmCachedInsns.size()) {
        free(reasmCachedInsns[index]);
        free(reasmCachedBytes[index]);
        free(reasmCachedErrors[index]);
        reasmCachedNBytes[index] = *outputLen;
        reasmCachedResults[index] = reasmResult;
        reasmCachedInsns[index] = strdup(str);
        reasmCachedBytes[index] = (char*)malloc(*outputLen);
        memcpy(reasmCachedBytes[index], byteBuf, *outputLen);
        reasmCachedErrors[index] = strdup(errorBuf);
    } else {
        reasmCachedNBytes.push_back(*outputLen);
        reasmCachedResults.push_back(reasmResult);
        reasmCachedInsns.push_back(strdup(str));
        reasmCachedBytes.push_back((char*)malloc(*outputLen));
        memcpy(reasmCachedBytes[index], byteBuf, *outputLen);
        reasmCachedErrors.push_back(strdup(errorBuf));
    }
    ++currentReasmCacheLine;
    if (currentReasmCacheLine >= REASM_CACHE_SIZE) {
        currentReasmCacheLine = 0;
    }
}

char reassemble(const char* bytes, int nBytes, const char* str, FILE* tmp, 
        const char* tmpname, char* byteBuf, int bufLen, int* outputLen,
        char* errorBuf, int errorBufLen) {

    ++numReassembled;
    char cacheResult;
    if (cacheFillResults(str, byteBuf, bufLen, outputLen, errorBuf, errorBufLen, &cacheResult)) {
        ++numReasmCacheHits;
        //std::cout << "RH: " << str << "\n";
        return cacheResult;
    }
    //std::cout << "R : " << str << "\n";

    static const char* as = Options::get("-as=");
    if (as == NULL) {
        std::cerr << "Must specify assembler with \"-as=\"\n";
        exit(-1);
    }
    static const char* asOpts = Options::get("-asopt=");
    static char** asArgv = makeAsArgs(as, asOpts, tmpname);

    char arrBuf[REASM_BUF_LEN];
    char* buf = &arrBuf[0];

    snprintf(buf, REASM_BUF_LEN, /*".global main\n\nmain:\n\t%s"*/"%s", str);
    //writeStrToFile(tmpname, 0, buf);
    
    struct timespec startTime;
    struct timespec endTime;
    clock_gettime(CLOCK_MONOTONIC, &startTime);
    int p[2];
    pipe(p);
    int p2[2];
    pipe(p2);
    int status;

    posix_spawn_file_actions_t action;

    posix_spawn_file_actions_init(&action);
    posix_spawn_file_actions_addclose(&action, p[0]);
    posix_spawn_file_actions_addclose(&action, p2[1]);
    posix_spawn_file_actions_adddup2(&action, p[1], STDERR_FILENO);
    posix_spawn_file_actions_adddup2(&action, p2[0], STDIN_FILENO);

    posix_spawn_file_actions_addclose(&action, p[1]);
    posix_spawn_file_actions_addclose(&action, p2[0]);

    pid_t pid;
    if (posix_spawnp(&pid, asArgv[0], &action, NULL, asArgv, NULL) != 0)
        std::cout << "posix_spawnp failed with error: " << strerror(errno) << "\n";

    posix_spawn_file_actions_destroy(&action);

    close(p[1]);
    close(p2[0]);
    
    //pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid > 0) {
        int toWrite = strlen(str);
        int written = write(p2[1], str, toWrite);
        assert(written == toWrite && "File write failed");
        write(p2[1], "\n", 1);
        //close(p2[0]);
        //close(p[1]);
        close(p2[1]);
        char c;
        int assemblerErrorTabCount = 5;
        int tabCount = 0;
        char* errorBufEnd = errorBuf + errorBufLen;
        char* curErrChar = errorBuf;
        while (read(p[0], &c, 1) > 0 && curErrChar < errorBufEnd) {
            if (tabCount >= assemblerErrorTabCount && c != '\n') {
                *curErrChar = c;
                ++curErrChar;
            }
            if (c == ':') {
                tabCount++;
            }
        }
        *curErrChar = '\0';
        close(p[0]);
        waitpid(pid, &status, 0);
    } else {
        close(p2[1]);
        dup2(p2[0], STDIN_FILENO);
        close(p2[0]);
        dup2(p[1], STDERR_FILENO);
        close(p[1]);
        close(p[0]);
        char* envp = NULL;
        execve(asArgv[0], asArgv, &envp);
        std::cout << strerror(errno) << "\n";
        assert(false && "execve() should never return");
    }

    clock_gettime(CLOCK_MONOTONIC, &endTime);
    totalReasmTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                  (endTime.tv_nsec - startTime.tv_nsec);
    if (status != 0) {
        cacheAddResults(str, byteBuf, bufLen, outputLen, errorBuf, errorBufLen, 'E');
        return 'E';
    }

    *outputLen = readReassembledBytes(tmpname, byteBuf, bufLen);
    if (*outputLen != nBytes || memcmp(byteBuf, bytes, *outputLen)) {
        cacheAddResults(str, byteBuf, bufLen, outputLen, errorBuf, errorBufLen, 'D');
        //clock_gettime(CLOCK_MONOTONIC, &endTime);
        //totalReasmTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
        //                              (endTime.tv_nsec - startTime.tv_nsec);
        return 'D';
    }
    cacheAddResults(str, byteBuf, bufLen, outputLen, errorBuf, errorBufLen, 'S');
    //clock_gettime(CLOCK_MONOTONIC, &endTime);
    //totalReasmTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
    //                              (endTime.tv_nsec - startTime.tv_nsec);
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

int retrieve_data(const char* filename, char* outBytes, int bufLen) {
  int fd;       // File descriptor for the executable ELF file
  char *section_name;
  size_t shstrndx;

  Elf* e;           // ELF struct
  Elf_Scn* scn;     // Section index struct
  Elf64_Shdr* shdr;     // Section struct

  if(elf_version(EV_CURRENT)==EV_NONE)
    errx(EXIT_FAILURE, "ELF library iinitialization failed: %s", elf_errmsg(-1));

  if((fd = open(filename, O_RDONLY, 0))<0)
    err(EXIT_FAILURE, "open \"%s\" failed", filename);

  if((e = elf_begin(fd, ELF_C_READ, NULL))==NULL)
    errx(EXIT_FAILURE, "elf_begin() failed: %s.", elf_errmsg(-1));

  // Retrieve the section index of the ELF section containing the string table of section names
  if(elf_getshdrstrndx(e, &shstrndx)!=0)
    errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));

  scn = NULL;

  size_t codeSize = 0;
  // Loop over all sections in the ELF object
  while((scn = elf_nextscn(e, scn))!=NULL) {
    
    // Given a Elf Scn pointer, retrieve the associated section header
    if((shdr = elf64_getshdr(scn))!=shdr)
      errx(EXIT_FAILURE, "getshdr() failed: %s.", elf_errmsg(-1));

    // Retrieve the name of the section name
    if((section_name = elf_strptr(e, shstrndx, shdr->sh_name))==NULL)
      errx(EXIT_FAILURE, "elf_strptr() failed: %s.", elf_errmsg(-1));

    // If the section is the one we want... (in my case, it is one of the main file sections)
    if(!strcmp(section_name, ".text")) {
      // We can use the section adress as a pointer, since it corresponds to the actual
      // adress where the section is placed in the virtual memory
      //struct data_t * codeBytes = (struct data_t *) shdr->sh_addr;
      codeSize = shdr->sh_size;
      size_t codeOffset = shdr->sh_offset;
      const char* codeBytes = (const char*) shdr->sh_addr;

      // Do whatever we want
      assert(shdr->sh_size <= (size_t)bufLen && "ERROR: reassembly byte buffer is too small");
      elf_end(e);
      lseek(fd, codeOffset, SEEK_SET);
      if (read(fd, outBytes, codeSize) != codeSize) {
        std::cerr << "ERROR: Could not read text section of " << filename << "\n";
        exit(-1);
      }
      close(fd);
      return codeSize;

      // End the loop (if we only need this section)
      break;
    }
  }

  elf_end(e);
  close(fd);
  return codeSize;
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

    int ASM_POS = 0;
    snprintf(str, REASM_BUF_LEN, "%s.o"/*.dmp*/, filename);
  
    return retrieve_data(str, outBytes, bufLen);
    //int p[2];
    //pipe(p);
    
    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid > 0) {
        // We are the parent, continue below
    } else {
        //dup2(p[1], STDOUT_FILENO);
        //close(p[1]);
        //close(p[0]);
        char* envp = NULL;
        FILE* outfile = fopen(str, "w+");
        dup2(fileno(outfile), STDOUT_FILENO);
        fclose(outfile);
        execve(objdumpArgv[0], objdumpArgv, &envp);
        std::cout << strerror(errno) << "\n";
        assert(false && "execve() should never return");
    }
    //close(p[1]);
    /*
    size_t bytesRead = 0;
    size_t rc = 0;
    char* cur = str;
    while ((rc = read(p[0], &cur, REASM_BUF_LEN - bytesRead)) > 0) {
        bytesRead += rc;
        cur += rc;
    }
    std::cout << str << "\n";*/
    //close(p[0]);
    waitpid(pid, &status, 0);
    
    snprintf(str, REASM_BUF_LEN, "%s.o", filename);
    FILE* asmFile = fopen(str, "r+");
    fseek(asmFile, ASM_POS, SEEK_SET);
    size_t len = fread(str, 1, REASM_BUF_LEN, asmFile);
    for (size_t j = 0; j < len; j++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << (unsigned int)(unsigned char)outBytes[j] << " ";
    }
    std::cout << std::dec << "\n";

    for (size_t i = 0; i < len; ++i) {
        if (outBytes[i] == (char)0xb4) {
            std::cout << "First byte at pos: " << i << "\n";
            exit(-1);
        }
    }
    std::cout << "Could not find byte\n";
    exit(-1);

    snprintf(str, REASM_BUF_LEN, "%s.dmp", filename);
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

