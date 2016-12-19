
#include "ReportingContext.h"

ReportingContext::ReportingContext(const char* outputDir, int flushFreq) {
  
    diffMap = new std::map<char*, std::list<Report*>*, StringUtils::str_cmp>();
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
    delete diffMap;
}

void ReportingContext::reportDiff(Report* report) {
    reportQueue.push(new Report(report));
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

        for (size_t i = 0; i < r->size(); i++) {
            if (r->hasReasmError(i)) {
                snprintf(filename, REPORT_FILENAME_BUF_LEN,
                        "%s/%s/%s.txt", outputDir, decoderNames[i],
                        asmErrorToFilename(r->getReasmError(i)).c_str());
                r->issue(filename);
                issuedToDecoder = true;
            }
        }

        // If there were not reassembly errors, then any decoder reporting the
        // instruction as invalid should have the instruction listed as a
        // potential error.
        if (!issuedToDecoder) {
            for (size_t i = 0; i < r->size(); i++) {
                if (r->getAsm(i)->isError()) {
                    snprintf(filename, REPORT_FILENAME_BUF_LEN,
                            "%s/%s/errors.txt", outputDir, decoderNames[i]);
                    r->issue(filename);
                    issuedToDecoder = true;
                }
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

int ReportingContext::processDecodings(std::vector<Assembly*>&
asmList) {
   
    
    // Update summary data.
    nProcessed++;

    // Check if every instruction matches the first. If they are all 
    // equivalent, there is no more processing to do, simply return.
    bool allMatch = true;
    auto asmIt = asmList.begin();
    assert(asmIt != asmList.end());
    Assembly* asm1 = *asmIt;
    ++asmIt;
    while (allMatch && asmIt != asmList.end()) {
        allMatch = asm1->isEquivalent(*asmIt);
        ++asmIt;
    }
    
    if (allMatch) {
       nMatches++;
       return asm1->getNBytes();
    }
    
    Report r = Report(asmList);

    // Check if we need to report the difference and do so. Update summary data.
    if (shouldReportDiff(&r)) {
        nReports++;
        reportDiff(&r);
    } else {
        nSuppressed++;
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
    char** insnTemplates = (char**)malloc(nInsns * sizeof(char*));
    char* buf = (char*)malloc(256 * nInsns);
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
    }
  
    // Check if we have seen this value before (including this time) less
    // than the threshold. If so, we will say that the difference
    // should be reported.
    
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
    free(buf);
    for (int i = 0; i < nInsns; i++) {
        free(insnTemplates[i]);
        delete tLists[i];
    }
    free(insnTemplates);

    return result;
}
