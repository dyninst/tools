
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

    /*
     * Constructs a ReassemblyDaemon object. This does NOT start a new process.
     */
    ReassemblyDaemon(const char* asName);

    /*
     * This is not yet implemented, so do NOT construct/destroy this object
     * expecting it to function well.
     */
    ~ReassemblyDaemon();

    /*
     * Starts the ReassemblyDaemon as a different process. You do NOT need to
     * fork prior to this process. It will fork as needed.
     */
    void start();

    /*
     * Uses pipes to send a string of assembly language to the daemon. The
     * daemon will fork an assembler which assembles the instruction. The
     * daemon will recieve any error message from the assembler and place it
     * in the buffer.
     *
     * Returns 0 on assembly success, non-zero on assembly error.
     */
    int reassemble(const char* str, char* errorBuf, int errorBufLen);

    /*
     * Returns the name of the binary file created by the assembler on
     * successful reassembly.
     */
    const char* getOutputFilename() { return outputFilename; }

    /*
     * The default name of the binary file created by the assembler.
     */
    const char* DEFAULT_AS_FILENAME = "/tmp/fl_rd.o";

    /*
     * A good standard buffer length for assembler error messages. This was
     * chosen empirically as the shortest power of 2 that could contain any
     * of the messages I encountered.
     */
    int ERROR_BUFFER_SIZE = 512;

    /*
     * A good standard buffer length to hold communication between the partent
     * process and the ReassemblyDaemon. This must be long enough to hold any
     * assembly language instruction and a few characters of control info.
     */
    int COMMAND_BUFFER_SIZE = 128;

private:

    /*
     * File descriptors for communication with the Reassembly Daemon.
     */
    int fleeceToDaemon;
    int daemonToFleece;

    /*
     * The name of the binary file created by the assembler.
     */
    const char* outputFilename;

    /*
     * The arguments passed to the assembler. This contains any options that
     * are needed for the specific syntax being used.
     */
    char** asArgs;

    /*
     * The starting point for the child process. This is where the daemon sits
     * and waits for instructions to reassemble.
     */
    void run();

    /*
     * Spawns an assembler process and gives it a string to reassemble.
     *
     * Returns 0 on assembler success, non-zero otherwise. When this function
     * returns non-zero, it places the error message from the assembler in
     * errorBuf, up to errorBufLen characters.
     */
    int spawnAssembler(const char* asmInsn, char* errorBuf, int errorBufLen);

    /*
     * A function that prints an error and exits.
     */
    void errexit(const char* buf);

    /*
     * This function does the work of writing the error message to the parent
     * process from the daemon process using the daemonToFleece file
     * descriptor.
     */
    void writeErrorMessageToParent(int status, char* errBuf);

    /*
     * The three functions below are used to format the arguments for the
     * assembler into the expected int argc, char** argv formats.
     */
    int getOptArgCount(const char* opts);
    void fillOptArgs(char** args, const char* opts);
    char** makeAsArgs(const char* as);
};

#endif // _REASSEMBLY_DAEMON_H_
