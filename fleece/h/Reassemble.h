
#ifndef REASSEMBLE_H_
#define REASSEMBLE_H_

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "Architecture.h"
#include "Options.h"
#include "StringUtils.h"

#define REASM_BUF_LEN 256
#define REASM_ERROR_BUF_LEN 256
#define BYTE_COLON_COUNT 4

extern const char* REASM_FILENAME;

enum AsmResult { 
    ASM_RESULT_NONE = 'N', 
    ASM_RESULT_ERROR = 'E', 
    ASM_RESULT_SAME = 'S', 
    ASM_RESULT_DIFFERENT = 'D' };

void initReassembly();
char reassemble(const char* bytes, int nBytes, const char* str, FILE* tmp, 
    const char* tmpname, char* byteBuf, int bufLen, int* outputLen,
    char* errorBuf, int errorBufLen);
int readReassembledBytes(const char* filename, char* outBytes, int bufLen);

#endif // REASSEMBLE_H_
