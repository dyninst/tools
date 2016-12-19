#ifndef _REPORT_H_
#define _REPORT_H_

#include <assert.h>
#include <errno.h>
#include <iostream>
#include <vector>
#include "Assembly.h"
#include "FieldList.h"
#include "StringUtils.h"

/*
 * This class records a single set of instructions, the input bytes that
 * produced them, and any reassembly errors that result.
 */
class Report {

public:

    Report(Report* r);

    /*
     * Creates a report from an array of disassembled instructions, the bytes
     * that caused these outputs and an array of errors from disassembly.
     */
    Report(std::vector<Assembly*>& asmList);

    /*
     * Destroys a report, freeing all acquired memory.
     */
    ~Report();

    /*
     * Appends this report to a provided filename. This will open, append to
     * and close the file.
     *
     * Note: This is inefficient because writes to the same files are not
     * grouped. This should be optimized if it proves to be a significant
     * portion of execution time.
     */
    void issue(const char* filename);

    /*
     * Returns an instruction according to an index into this report.
     */
    const char* getInsn (int index) { return asmList[index]->getString(); }

    /*
     * Returns true if there is a non-empty string for the reassembly error of
     * an index. If true, this means that the instruction at the given index
     * produced an error during the reassembly phase.
     */
    bool hasReasmError(int index) { 
            return !asmList[index]->isError() && asmList[index]->getAsmResult() == 'E'; }
    
    /*
     * Returns a c-style string containing the assembly error at a given index.
     * If this is the empty string, there is no error at that index.
     *
     * Does NOT perform bounds checking.
     */
    const char* getReasmError(int index) { 
            return asmList[index]->getAsmError(); }

    /*
     * Returns the number of instructions in this report.
     */
    size_t size() { return asmList.size(); }

    /*
     * Returns true if the two reports contain distinct differences between
     * their fields.
     */
    bool isEquivalent(Report* r);

    Assembly* getAsm(int index) { return asmList[index]; }

private:

    std::vector<Assembly*> asmList;

};

#endif // _REPORT_H_
