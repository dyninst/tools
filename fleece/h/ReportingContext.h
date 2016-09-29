#ifndef _REPORTING_CONTEXT_H_
#define _REPORTING_CONTEXT_H_

#include "Alias.h"
#include "Architecture.h"
#include "Reassemble.h"
#include "StringUtils.h"

/*
 * This class is used to keep track of the instruction templates we have
 * already seen. It filters reports that are similar to the ones we have
 * already seen and attempts to produce new ones.
 */
class ReportingContext {

public:

    /*
     * Creates a reporting context with the given output file. The file will
     * be flushed every flushFreq reports.
     */
    ReportingContext(FILE* outf, int flushFreq);

    /*
     * Destroys the reporting context. Does NOT close the output file (the
     * reporting context did not open it).
     */
    ~ReportingContext();

    /*
     * Takes an array of decoded instructions, and the bytes and produces a
     * report, if one should be produced based on what was previously seen.
     */
    int processDecodings(const char** insns, int nInsns, const char* bytes, 
            int nBytes);

    /*
     * Prints data about the activity of the reporting context.
     */
    void printSummary(FILE* outf);

    /*
     * Accessors for numerical data about the reporting activity.
     */
    unsigned int getNumReports();
    unsigned int getNumMatches();
    unsigned int getNumProcessed();
    unsigned int getNumSuppressed();

private:
   
    /*
     * Reports a difference to the file that was passed at creation time.
     */
    void reportDiff(const char** insns, int nInsns, const char* bytes, 
            int nBytes);

    /*
     * Examines the data already reported and decides if the incoming decodings
     * need to be reported as well.
     */
    bool shouldReportDiff(const char* bytes, int nBytes, 
        const char** insns, int nInsns);

    /*
     * Makes comparisons and looks up aliases to determine if two decodings
     * match eachother.
     */
    bool doesDecodingMatch(const char* insn1, const char* insn2);

    /*
     * Data used to summarize the activity of the reporting context.
     */
    unsigned int nReports;
    unsigned int nMatches;
    unsigned int nProcessed;
    unsigned int nSuppressed;

    /*
     * The record of different instruction decodings seen.
     */
    std::map<char*, int, StringUtils::str_cmp>* diffMap;

    /*
     * The output file for all reports (but not necessarily for summary data).
     */
    FILE* outFile;

    /*
     * The frequency (in reports) with which the report file should be flushed.
     */
    int flushFreq;
    int flushCount;
};

#endif // _REPORTING_CONTEXT_H_
