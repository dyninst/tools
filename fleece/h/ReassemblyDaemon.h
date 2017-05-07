
#ifndef REASSEMBLY_DAEMON_H_
#define REASSEMBLY_DAEMON_H_

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
#include "Reassemble.h"
#include "StringUtils.h"
#include <iostream>
#include <iomanip>
#include <libelf.h>
#include <err.h>
#include <fcntl.h>
#include <spawn.h>

/*
 * The ReassemblyDaemon class is intended to be used to assembling instructions without
 * the main process making repeated calls to fork. The main process forks once and the
 * child of the fork should execute ReassemblyDaemon::run(). Then, the main process
 * can call ReassemblyDaemon::reassemble(), and the child process will fork and exec to
 * call an assembler.
 */
class ReassemblyDaemon {
public:
    ReassemblyDaemon(const char* asName);

    ~ReassemblyDaemon();

    void start();
    int reassemble(const char* str, char* errorBuf, int errorBufLen);
    const char* getOutputFilename() { return outputFilename; }

    const char* DEFAULT_AS_FILENAME = "/tmp/fl_rd.o";
    int ERROR_BUFFER_SIZE = 512;
    int COMMAND_BUFFER_SIZE = 128;

private:
    int fleeceToDaemon;
    int daemonToFleece;
    const char* outputFilename;
    char** asArgs;

    void run();
    int spawnAssembler(const char* asmInsn, char* errorBuf, int errorBufLen);

    void errexit(const char* buf);

    void writeErrorMessageToParent(int status, char* errBuf);

    int getOptArgCount(const char* opts);

    void fillOptArgs(char** args, const char* opts);

    char** makeAsArgs(const char* as);
};

#endif // _REASSEMBLY_DAEMON_H_
