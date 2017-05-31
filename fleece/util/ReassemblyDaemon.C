
#include "ReassemblyDaemon.h"
#include <iostream>
#include <iomanip>
#include <libelf.h>
#include <err.h>
#include <fcntl.h>
#include <spawn.h>

#define COLONS_BEFORE_ERROR_MESSAGE 5

ReassemblyDaemon::ReassemblyDaemon(const char* asName) {
    // Initialization
    this->fleeceToDaemon = -1;
    this->daemonToFleece = -1;
    this->asArgs = makeAsArgs(asName);
    this->outputFilename = asArgs[2];
}

ReassemblyDaemon::~ReassemblyDaemon() {
    // Not sure what to do here yet.
}

void ReassemblyDaemon::start() {
    int fleeceToDaemon[2];
    int daemonToFleece[2];
    int rc = pipe(fleeceToDaemon);
    if (rc != 0) {
        std::cerr << "Error: failed to create pipe to reassembly daemon!\n";
        exit(-1);
    }
    rc = pipe(daemonToFleece);
    if (rc != 0) {
        std::cerr << "Error: failed to create pipe to reassembly daemon!\n";
        exit(-1);
    }
    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid == 0) {
        // We're the daemon.
        close(fleeceToDaemon[1]);
        close(daemonToFleece[0]);
        this->fleeceToDaemon = fleeceToDaemon[0];
        this->daemonToFleece = daemonToFleece[1];
        run();
        std::cerr << "The reassembly daemon should never return\n";
        exit(-1);
    }
    // We're the parent.
    close(fleeceToDaemon[0]);
    close(daemonToFleece[1]);
    this->fleeceToDaemon = fleeceToDaemon[1];
    this->daemonToFleece = daemonToFleece[0];
}

void ReassemblyDaemon::run() {
    char asmBuf[ReassemblyDaemon::COMMAND_BUFFER_SIZE];
    char errBuf[ReassemblyDaemon::ERROR_BUFFER_SIZE];
    char* cur = asmBuf;
    int rc;
    while ((rc = read(fleeceToDaemon, cur, ReassemblyDaemon::COMMAND_BUFFER_SIZE)) != 0) {
        cur += rc;
        --cur;
        if (*cur == '\n') {
            *cur = '\0';
            rc = spawnAssembler(asmBuf, errBuf, ReassemblyDaemon::ERROR_BUFFER_SIZE);
            writeErrorMessageToParent(rc, errBuf);
            cur = asmBuf;
        }
    }
    std::cerr << "ReassemblyDaemon: reached EOF on input pipe\n";
}

int ReassemblyDaemon::reassemble(const char* str, char* errorBuf, int errorBufLen) {
    int len = strlen(str);
    int rc = 0;
    int result = 0;
    const char* cur = str;
    while (len > 0 && (rc == write(fleeceToDaemon, cur, len)) != 0) {
        len -= rc;
        cur += rc;
    }
    rc = write(fleeceToDaemon, "\n", 1);
    if (rc != 1) {
        errexit("Could not write assembly string to daemon process\n");
    }
    char* errPlace = errorBuf;
    char* endErrorBuf = errorBuf + errorBufLen;
    bool done = false;
    while (errPlace < endErrorBuf && !done) {
        rc = read(daemonToFleece, errPlace, 1);
        if (rc != 1) {
            errexit("Could not read from daemon process\n");
        }
        if (*errPlace == '~') {
            *(errPlace + 1) = '\0';
            done = true;
            if (*(errPlace - 1) != 'S') {
                result = 1;
            }
            *(errPlace - 1) = '\0';
        }
        ++errPlace;
    }
    assert(done && "Could not receive full error message from assembler");
    return result;
}

int ReassemblyDaemon::spawnAssembler(const char* asmInsn, char* errorBuf, int errorBufLen) {
    // Open a pipe that will be used to write bytes to the assembler
    int daemonToAs[2];
    int asToDaemon[2];
    int status;
   
    if (pipe(daemonToAs) != 0) {
        std::cerr << "ERROR: could not make pipe: " << strerror(errno) << "\n";
        exit(-1);
    }
    if (pipe(asToDaemon) != 0) {
        std::cerr << "ERROR: could not make pipe: " << strerror(errno) << "\n";
        exit(-1);
    }

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork() for reassembly\n";
        exit(-1);
    } else if (pid > 0) {

        // Close child-sides of the pipe.
        close(daemonToAs[0]);
        close(asToDaemon[1]);

        // Write the assembly language string to the assembler, followed by a new line.
        int toWrite = strlen(asmInsn);
        int written = write(daemonToAs[1], asmInsn, toWrite);
        if (written != toWrite) {
            errexit("Failed to write to \'as\' process");
        }
        if (write(daemonToAs[1], "\n", 1) != 1) {
            errexit("Failed to write to \'as\' process");
        }
        
        // Close the pipe that was used to send assembly language to assembler.
        close(daemonToAs[1]);

        // Read the stderr from the assembler.
        char c;
        int colonCount = 0;
        char* errorBufEnd = errorBuf + errorBufLen;
        char* curErrChar = errorBuf;
        while (read(asToDaemon[0], &c, 1) > 0 && curErrChar < errorBufEnd) {
            if (colonCount >= COLONS_BEFORE_ERROR_MESSAGE && c != '\n') {
                *curErrChar = c;
                ++curErrChar;
            }
            if (c == ':') {
                colonCount++;
            }
        }
        // Make sure the error message buffer is null-terminated.
        *curErrChar = '\0';

        // Close the pipe used to read error messages.
        close(asToDaemon[0]);

        // Wait until the assember has finished.
        waitpid(pid, &status, 0);
    } else {
        close(daemonToAs[1]);
        close(asToDaemon[0]);
        dup2(daemonToAs[0], STDIN_FILENO);
        close(daemonToAs[1]);
        dup2(asToDaemon[1], STDERR_FILENO);
        close(asToDaemon[1]);
        char* envp = NULL;
        execve(asArgs[0], asArgs, &envp);
        errexit("execve() should never return");
    }
    return status;
}

void ReassemblyDaemon::errexit(const char* buf) {
    std::cerr << buf << std::endl;
    exit(-1);
}

void ReassemblyDaemon::writeErrorMessageToParent(int status, char* errBuf) {
    char* cur = errBuf;
    int rc;
    while (*cur && (rc = write(daemonToFleece, cur, 1)) == 1) {
        ++cur;
    }
    if (status != 0) {
        rc = write(daemonToFleece, "F", 1);
        if (rc != 1) {
            errexit("Could not write to parent process\n");
        }
    } else {
        rc = write(daemonToFleece, "S", 1);
        if (rc != 1) {
            errexit("Could not write to parent process\n");
        }
    }
    rc = write(daemonToFleece, "~", 1);
    if (rc != 1) {
        errexit("Could not write to parent process\n");
    }
}

int ReassemblyDaemon::getOptArgCount(const char* opts) {
    
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

void ReassemblyDaemon::fillOptArgs(char** args, const char* opts) {
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

char** ReassemblyDaemon::makeAsArgs(const char* as) {

    const char* asOpts = Options::get("-asopt=");
    const int nNeededArgs = 4;
    int nOptArgs = getOptArgCount(asOpts);
    const char* givenFilename = Options::get("-asf=");
    char* filename;
    if (givenFilename == NULL) {
        filename = strdup(ReassemblyDaemon::DEFAULT_AS_FILENAME);
    } else {
        filename = strdup(givenFilename);
    }
    
    char** result = (char**)malloc(sizeof(*result)*(nOptArgs + nNeededArgs));
    assert(result != NULL);

    result[0] = strdup(as);
    result[1] = strdup("-o");
    result[2] = (char*)filename;

    if (nOptArgs > 0) {
        fillOptArgs(&result[3], asOpts);
    }

    result[nOptArgs + nNeededArgs - 1] = NULL;
    return result;
}

