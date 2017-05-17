#ifndef _REPORT_H_
#define _REPORT_H_

#include <assert.h>
#include <errno.h>
#include <iostream>
#include <vector>
#include "Assembly.h"
#include "FieldList.h"
#include "StringUtils.h"

extern unsigned long long totalReportIssueTime;

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
     * Appends this report to a provided file.
     */
    void issue(FILE* file);

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

    /*
     * Returns a string containing the templates of all instructions in this
     * report.
     */
    void makeTemplate(char* buf, size_t bufLen);

    /*
     * Returns a pointer to a specific Assembly object in this report.
     *
     * Note: The assembly structure is not const, but altering it will alter
     * the report, so it should be treated as const.
     */
    Assembly* getAsm(int index) { return asmList[index]; }

    /*
     * Prints debug information for this object.
     */
    void printDebug();

private:

    /*
     * The list of Assembly objects used in this report.
     */
    std::vector<Assembly*> asmList;

};

#endif // _REPORT_H_
