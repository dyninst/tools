
#include "ReportingContext.h"

ReportingContext::ReportingContext(const char* outputDir, int flushFreq) {
  
    diffMap = new std::map<char*, int, StringUtils::str_cmp>();
    assert(diffMap != NULL && "Report hashcounter should not be null!");

    // Initialize summary data to all zeroes.
    nProcessed = 0;
    nMatches = 0;
    nReports = 0;
    nSuppressed = 0;

    this->outputDir = strdup(outputDir);

    this->flushFreq = flushFreq;
    flushCount = 0;
}

ReportingContext::~ReportingContext() {

    flushReportQueue();
    
    free(outputDir);

    // We only need to delete the difference counter, since the file was passed
    // as an already-opened FILE*, someone else is responsible.
    assert(diffMap != NULL && "Report difference map should not be null!");

    delete diffMap;
}

void ReportingContext::reportDiff(const char** insns, int nInsns, 
        const char* bytes, int nBytes, const char** reasmErrors) {
  
    reportQueue.push(new Report(insns, nInsns, bytes, nBytes, reasmErrors));
    flushCount++;
    if (flushCount > flushFreq) {
        flushReportQueue();
        flushCount = 0;
    }
}

void ReportingContext::flushReportQueue() {
    while (!reportQueue.empty()) {

        // Read the next report from the queue.
        Report* r = reportQueue.front();
        reportQueue.pop();

        // Construct a buffer for the filenames to be written to.
        char filenameBuf[REPORT_FILENAME_BUF_LEN];
        char* filename = &filenameBuf[0];

        // All reports are issued to the all_reports.txt file.
        snprintf(filename, REPORT_FILENAME_BUF_LEN, "%s/all_reports.txt",
                outputDir);
        r->issue(filename);

        // We need to track whether or not a report has been issued to at least
        // one decoder. If not, we can add it to the no_obv_error file.
        bool issuedToDecoder = false;

        // Issue reports to each decoder that interpreted an instruction as
        // invalid.
        for (size_t i = 0; i < r->size(); i++) {
            FieldList fl = FieldList(r->getInsn(i));
            if (fl.hasError()) {
                snprintf(filename, REPORT_FILENAME_BUF_LEN,
                        "%s/%s/errors.txt", outputDir, decoderNames[i]);
                r->issue(filename);
                issuedToDecoder = true;
            } else if (r->hasReasmError(i)) {
                snprintf(filename, REPORT_FILENAME_BUF_LEN,
                        "%s/%s/%s.txt", outputDir, decoderNames[i],
                        asmErrorToFilename(r->getReasmError(i)).c_str());
                r->issue(filename);
                issuedToDecoder = true;
            }
        }

        // If there were no failures to decode and all outputs assembled, add
        // it to the no obvious error file. This should be renamed, but will
        // suffice for now.
        if (!issuedToDecoder) {
            snprintf(filename, REPORT_FILENAME_BUF_LEN, "%s/no_obv_error.txt",
                    outputDir);
            r->issue(filename);
        }

        // Reports were created using new and put on the queue, so free them
        // here.
        delete r;
    }
}

void ReportingContext::addDecoder(const char* name) {
    decoderNames.push_back(strdup(name));
}

int ReportingContext::processDecodings(const char** insns, int nInsns, 
        const char* bytes, int nBytes) {
   
    // Update summary data.
    nProcessed++;

    // Check if every instruction matches the first. If they are all 
    // equivalent, there is no more processing to do, simply return.
    bool allMatch = true;
    for (int i = 1; allMatch && i < nInsns; i++) {
        allMatch = doesDecodingMatch(insns[0], insns[i]);
    }

    char reasmResults[nInsns + 1];
    char reasmErrorBufs[nInsns][REASM_ERROR_BUF_LEN];
    char* reasmErrors[nInsns];
    for (int i = 0; i < nInsns; i++) {
        reasmErrors[i] = &reasmErrorBufs[i][0];
    }
    if (!allMatch) {
        int nAgreed = 0;
        char reasmDiffBuf[15];
        reasmResults[nInsns] = 0;
        for (int i = 0; i < nInsns; i++) {
        
            reasmErrors[i][0] = '\0';
            FieldList f = FieldList(insns[i]);
            char reasmBuf[15];
            int reasmLen = 0;
            if (f.hasError()) {
                reasmResults[i] = 'N';
            } else {
                reasmResults[i] = reassemble(bytes, nBytes, insns[i], NULL, 
                    REASM_FILENAME, &reasmBuf[0], 15, &reasmLen,
                    &reasmErrors[i][0], REASM_ERROR_BUF_LEN);

                if (reasmResults[i] != 'E') {
                    if (i == 0) {
                        nAgreed++;
                        memcpy(reasmDiffBuf, reasmBuf, reasmLen);
                    } else {
                        if (!memcmp(reasmBuf, reasmDiffBuf, reasmLen)) {
                            nAgreed++;
                        }
                    }
                }
            }
        }

        if (nAgreed == nInsns) {
            FILE* sameF = fopen("same.txt", "a+");
            for (int i = 0; i < nInsns; i++) {
                fprintf(sameF, "%s; ", insns[i]);
                //std::cout << insns[i] << "\n";
            }
            fprintf(sameF, "%s\n", reasmResults);
            //std::cout << "REASSEMBLY: " << reasmResults << "\n";
            fclose(sameF);
            allMatch = true;
        }
    }

    if (allMatch) {
       nMatches++;
       return nBytes;
    }

    // Check if we need to report the difference and do so. Update summary data.
    if (shouldReportDiff(bytes, nBytes, insns, nInsns)) {
        nReports++;
        reportDiff(insns, nInsns, bytes, nBytes, (const char**)&reasmErrors[0]);
    } else {
        nSuppressed++;
    }

    return nBytes;
}

void ReportingContext::printSummary(FILE* outf) {

    // Verify that we have a valid file and report data.
    assert(outf != NULL && "File for summary should not be null!");

    fprintf(outf, "%d, %d, %d\n", nReports, nMatches, nSuppressed);
   
    // Below is data formatted better for human reading, but worse for periodic
    // reporting to measure activity over time, so it has be commented out.

    /*
    fprintf(outf, "%d instructions were processed, of which:\n", nProcessed);
    fprintf(outf, "\t%d were decoded the same\n", nMatches);
    fprintf(outf, "\t%d resulted in unique reports\n", nReports);
    fprintf(outf, "\t%d resulted in duplicate reports\n", nSuppressed);
    */
}

unsigned int ReportingContext::getNumReports() {
    return nReports;
}

unsigned int ReportingContext::getNumMatches() {
    return nMatches;
}

unsigned int ReportingContext::getNumProcessed() {
    return nProcessed;
}

unsigned int ReportingContext::getNumSuppressed() {
    return nSuppressed;
}

bool ReportingContext::shouldReportDiff(const char* bytes, int nBytes, 
        const char** insns, int nInsns) {

    // Allocate buffers for the instruction templates and output.
    char** insnTemplates = (char**)malloc(nInsns * sizeof(char*));
    char* buf = (char*)malloc(256 * nInsns);
    char* end = buf + 256 * nInsns;
    assert(insnTemplates != NULL && buf != NULL);

    // We're going to convert each instruction to a list of fields.
    std::vector<FieldList*> tLists;

    int nFields;
    for (int i = 0; i < nInsns; i++) {
        tLists.push_back(new FieldList(insns[i]));

        // Strip the hex and dec numbersfrom each list.
        tLists[i]->stripHex();
        tLists[i]->stripDigits();

        // If they all have the same number of fields, we can check
        // to see if there are individual differences.
        if (i == 0) {
            nFields = tLists[i]->size();
        } else {

            // If any isn't equal, set the count to -1, since that will be an
            // error value.
            if (tLists[i]->size() != (size_t)nFields) {
                nFields = -1;
            }
        }
        
        Architecture::replaceRegSets(*(tLists[i]));

        // Leave some room for extra register value.
        int len = tLists[i]->getTotalBytes();

        insnTemplates[i] = (char*)malloc(len);
        assert(insnTemplates[i] != NULL);

        // Take the stripped field list and make a buffer we can turn into the
        // template by replacing register sets.
        tLists[i]->fillBuf(insnTemplates[i], len);
  
    }

    bool result = false;
    char* cur = buf;
    // If we still think the difference should be reported, now make a string
    // with all instruction templates.
    for (int j = 0; j < nInsns; j++) {
     
        strncpy(cur, insnTemplates[j], end - cur);

        while (*cur && cur < end) {
            cur++;
        }
     
        if (cur < end) {
            *cur = ';';
            cur++;
        }
    }
  
    // Check if we have seen this value before (including this time) less
    // than the threshold. If so, we will say that the difference
    // should be reported.
    if (diffMap->count(buf) == 0) {
        result = true;
        diffMap->insert(std::make_pair(strdup(buf), 1));
    }
   
    // Free the buffer and templates used and delete the field lists.
    free(buf);
    for (int i = 0; i < nInsns; i++) {
        free(insnTemplates[i]);
        delete tLists[i];
    }
    free(insnTemplates);

    return result;
}


bool ReportingContext::doesDecodingMatch(const char* insn1, const char* insn2) {
   
    // If the two strings are the same, the decodings match. Since this happens
    // often, we should check it first.
    if (!strcmp(insn1, insn2)) {
        return true;
    }

    FieldList tList1(insn1);
    FieldList tList2(insn2);

    /*
     * First, determine if either of the decoded results produced any fields
     * that signal an error during decoding. Errors are assumed to be
     * equivalent.
     */
    bool errIn1 = tList1.hasError();
    bool errIn2 = tList2.hasError();

    /*
     * Either both must be an error, or both must not. Otherwise, the decodings
     * do not match.
     */
    if (errIn1 && errIn2) {
        return true;
    } else if (errIn1 || errIn2) {
        return false;
    }

    /*
     * If the number of fields in the lists are different, the decodings do not
     * match.
     */
    if (tList1.size() != tList2.size()) {
        return false;
    }

    /*
     * If any of the fields are NOT aliases of the corresponding field in the
     * other list, then the decodings do not match.
     */
    for (unsigned int i = 0; i < tList1.size(); i++) {
        if (strcmp(tList1.getField(i), tList2.getField(i)) &&
             !Alias::isAlias(tList1.getField(i), tList2.getField(i))) {
            return false;
        }
    }

    /*
     * If we're here, it means that the decodings have the same number of
     * fields, and those fields are either identical, or they are aliases of
     * eachother.
     */
    return true;
}

