
#include <fcntl.h>
#include "ReportingContext.h"

ReportingContext::ReportingContext(const char* outputDir, int flushFreq) {
  
    diffMap = new std::map<char*, std::list<Report*>*, StringUtils::str_cmp>();
    matchMap = new std::map<char*, Report*, StringUtils::str_cmp>();
    fileMap = new std::map<char*, FILE*, StringUtils::str_cmp>();
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

    for (auto it = diffMap->begin(); it != diffMap->end(); ++it) {
        delete it->second;
    }
    for (auto it = matchMap->begin(); it != matchMap->end(); ++it) {
        delete it->second;
    }
    for (auto it = fileMap->begin(); it != fileMap->end(); ++it) {
        fclose(it->second);
    }
    delete diffMap;
}

FILE* ReportingContext::getOpenFileByName(const char* filename) {
    //std::cout << "Getting open file " << filename << "\n";
    auto fileMapEntry = fileMap->find((char*)filename);
    if (fileMapEntry == fileMap->end()) {
        FILE* outf = fopen(filename, "a+");
        assert(outf != NULL);
        fcntl(fileno(outf), F_SETFD, fcntl(fileno(outf), F_GETFD) | FD_CLOEXEC);
        fileMap->insert(std::make_pair(strdup(filename), outf));
        return outf;
    } else {
        return fileMapEntry->second;
    }
}

void ReportingContext::closeOpenFiles() {
    auto it = fileMap->begin();
    while (it != fileMap->end()) {
        fclose(it->second);
        free(it->first);
        it = fileMap->erase(it);
    }
}

void ReportingContext::reportDiff(Report* r) {
    reportQueue.push(new Report(r));
    flushCount++;
    if (flushCount >= flushFreq) {
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
        FILE* outf = getOpenFileByName(filename);
        r->issue(outf);

        // We need to track whether or not a report has been issued to at least
        // one decoder. If not, we can add it to the no_obv_error file.
        bool issuedToDecoder = false;
        bool anyValid = false;

        // First, issue a report to for all decoders whose output could not be reassembled.
        for (size_t i = 0; i < r->size(); i++) {
            if (r->hasReasmError(i)) {
                snprintf(filename, REPORT_FILENAME_BUF_LEN,
                        "%s/%s/%s.txt", outputDir, decoderNames[i],
                        asmErrorToFilename(r->getReasmError(i)).c_str());
                outf = getOpenFileByName(filename);
                r->issue(outf);
                issuedToDecoder = true;
            } else if (!r->getAsm(i)->isError()) {
                anyValid = true;
            }
        }

        // If there were no reassembly errors, then any decoder reporting the
        // instruction as invalid or which reassembled differently than
        // the input should have the instruction listed as a
        // potential error.
        if (anyValid) {
            for (size_t i = 0; i < r->size(); ++i) {
                if (r->getAsm(i)->isError()) {
                    snprintf(filename, REPORT_FILENAME_BUF_LEN,
                            "%s/%s/returned_invalid.txt", outputDir, decoderNames[i]);
                    outf = getOpenFileByName(filename);
                    r->issue(outf);
                    issuedToDecoder = true;
                }
            }

            const char* reasmBytes;
            size_t nReasmBytes = 0;
            bool reasmAgrees = true;
            for (size_t i = 0; i < r->size(); ++i) {
                Assembly* curAsm = r->getAsm(i);
                if (!curAsm->isError() && curAsm->getAsmResult() != AsmResult::ASM_RESULT_ERROR) {
                    const char* curReasmBytes = curAsm->getAsmBytes();
                    size_t curNReasmBytes = curAsm->getNAsmBytes();
                    if (nReasmBytes == 0) {
                        nReasmBytes = curNReasmBytes;
                        reasmBytes = curReasmBytes;
                    } else {
                        if (nReasmBytes != curNReasmBytes) {
                            reasmAgrees = false;
                        } else if (memcmp(reasmBytes, curReasmBytes, nReasmBytes)) {
                            reasmAgrees = false;
                        }
                    }
                }
            }

            if (!reasmAgrees) {
                for (size_t i = 0; i < r->size(); ++i) {
                    Assembly* curAsm = r->getAsm(i);
                    if (curAsm->getAsmResult() == AsmResult::ASM_RESULT_DIFFERENT) {
                        snprintf(filename, REPORT_FILENAME_BUF_LEN,
                                "%s/%s/diff_reasm.txt", outputDir, decoderNames[i]);
                        outf = getOpenFileByName(filename);
                        r->issue(outf);
                        issuedToDecoder = true;
                    }
                }
            }
        }

        // If there were no failures to decode and all outputs assembled, and
        // the outputs assembled to the same bytes, then we're really confused.
        // This should never happen, because all types of errors we identify
        // are already reported by this point.
        if (!issuedToDecoder) {
            snprintf(filename, REPORT_FILENAME_BUF_LEN, "%s/unknown_issue.txt",
                    outputDir);
            outf = getOpenFileByName(filename);
            r->issue(outf);
        }

        // Reports were created using new and put on the queue, so delete them
        // here.
        delete r;
    }
    closeOpenFiles();
}

void ReportingContext::addDecoder(const char* name) {
    decoderNames.push_back(strdup(name));
}

int ReportingContext::processDecodings(std::vector<Assembly*>& asmList) {
   
    // Update summary data.
    nProcessed++;
    
    // Check if every instruction matches the first. If they are all 
    // equivalent, there is no more processing to do, simply return.
    bool allMatch = true;
    auto asmIt = asmList.begin();
    while (asmIt != asmList.end()) {
        (*asmIt)->getAsmResult();
        ++asmIt;
    }
    asmIt = asmList.begin();
    assert(asmIt != asmList.end());
    Assembly* asm1 = *asmIt;
    ++asmIt;
    while (allMatch && asmIt != asmList.end()) {
        allMatch = asm1->isEquivalent(*asmIt);
        ++asmIt;
    }
    
    Report r = Report(asmList);
    
    // We want to only report unique matches, so we need to keep track of which instructions we
    // have seen for matches. All others should count as suppressed.
    if (allMatch) {
       /*
       char* buf = (char*)malloc(256 * r.size());
       assert(buf != NULL);
       r.makeTemplate(buf, 256 * r.size());
       if (matchMap->count(buf) == 0) {
          ++nMatches;
          matchMap->insert(std::make_pair(strdup(buf), new Report(&r)));
       } else {
          ++nSuppressed;
       }
       free(buf);
       */
       ++nMatches;
       return asm1->getNBytes();
    }

    if (Options::get("-rand") != NULL) {
        // Check if we need to report the difference and do so. Update summary data.
        if (shouldReportDiff(&r)) {
            nReports++;
            reportDiff(&r);
        } else {
            nSuppressed++;
        }
    } else {
        nReports++;
        reportDiff(&r);
    }

    return asm1->getNBytes();

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

bool ReportingContext::shouldReportDiff(Report* report) {

    int nInsns = report->size();

    // Allocate buffers for the instruction templates and output.
    //char** insnTemplates = (char**)malloc(nInsns * sizeof(char*));
    char buf[256 * nInsns];
    //char* buf = (char*)malloc(256 * nInsns);
    report->makeTemplate(buf, 256 * nInsns);
    
    /*
    char* end = buf + 256 * nInsns;
    assert(insnTemplates != NULL && buf != NULL);

    // We're going to convert each instruction to a list of fields.
    std::vector<FieldList*> tLists;

    int nFields;
    for (int i = 0; i < nInsns; i++) {
        tLists.push_back(new FieldList(report->getInsn(i)));

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
    }*/
  
    // Check if we have seen this value before (including this time) less
    // than the threshold. If so, we will say that the difference
    // should be reported.
    
    bool result = false;
    if (diffMap->count(buf) == 0) {
        result = true;
        std::list<Report*>* newList = new std::list<Report*>();
        newList->push_back(new Report(report));
        diffMap->insert(std::make_pair(strdup(buf), newList));
    } else {
        bool foundEquivalent = false;
        std::list<Report*>* oldReports = (*(diffMap->find(buf))).second;
        for (auto it = oldReports->begin(); it != oldReports->end(); ++it) {
            if (report->isEquivalent(*it)) {
                foundEquivalent = true;
            }
        }
        if (!foundEquivalent) {
            oldReports->push_back(new Report(report));
            result = true;
        }
    }
   
    // Free the buffer and templates used and delete the field lists.
    //free(buf);
    /*
    for (int i = 0; i < nInsns; i++) {
        free(insnTemplates[i]);
        delete tLists[i];
    }
    free(insnTemplates);
    */
    return result;
}
