
#include "ReportingContext.h"

ReportingContext::ReportingContext(const char* outputDir, int flushFreq) {
  
    diffMap = new std::map<char*, std::list<Report*>*, StringUtils::str_cmp>();
    fileMap = new std::map<char*, FILE*, StringUtils::str_cmp>();
    assert(diffMap != NULL && fileMap != NULL && "ReportingContext failed to allocate std::maps");

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
    
    closeOpenFiles();
    delete fileMap;
}

FILE* ReportingContext::getOpenFileByName(const char* filename) {
    auto fileMapEntry = fileMap->find((char*)filename);
    
    // Check if we have already opened the file.
    if (fileMapEntry == fileMap->end()) {

        // The file was not already open, so open it in append mode.
        FILE* outf = fopen(filename, "a+");
        assert(outf != NULL);
        fileMap->insert(std::make_pair(strdup(filename), outf));

        // Determine file length. If the file was empty, then we should write a
        // header indicating which decoder is responsible for which output
        // column.
        fseek(outf, 0, SEEK_END);
        size_t flen = ftell(outf);
        fseek(outf, 0, SEEK_SET);
        if (flen == 0) {
            writeHeader(outf);
        }

        return outf;
    } else {

        // The file was already open, so return the stored pointer.
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

void ReportingContext::writeHeader(FILE* outf) {
    for (size_t i = 0; i < decoderNames.size(); ++i) {
        fprintf(outf, "%s; ", decoderNames[i]);
    }
    fprintf(outf, "bytes\n");
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
        // one decoder. If not, we can add it to the unknown_issue.txt file.
        bool issuedToDecoder = false;
        bool anyValid = false;

        // First, issue a report to all decoders whose output could not be reassembled.
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
        // instruction as invalid or which reassembled differently than the 
        // input should have the instruction listed as a potential error.
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
    assert(outf != NULL && "File for summary should not be null!");
    fprintf(outf, "Reports: %d, Matches: %d, Suppressed: %d\n", nReports, nMatches, nSuppressed);
}

bool ReportingContext::shouldReportDiff(Report* report) {

    int nInsns = report->size();

    // Allocate buffers for the instruction templates and output.
    char buf[256 * nInsns];
    report->makeTemplate(buf, 256 * nInsns);
  
    // Check if we have seen this value before (including this time) less
    // than the threshold. If so, we will say that the difference
    // should be reported.
    bool result = false;
    if (diffMap->count(buf) == 0) {

        // If no report with this template has been seen, create a new list
        // of unique reports and add this report to it.
        result = true;
        std::list<Report*>* newList = new std::list<Report*>();
        newList->push_back(new Report(report));
        diffMap->insert(std::make_pair(strdup(buf), newList));
    } else {

        // A report with this template has been seen, but the reports might
        // not be equivalent. If they are not, issue this new report and store
        // it.
        bool foundEquivalent = false;
        std::list<Report*>* oldReports = (*(diffMap->find(buf))).second;
        for (auto it = oldReports->begin(); !foundEquivalent && it != oldReports->end(); ++it) {
            if (report->isEquivalent(*it)) {
                foundEquivalent = true;
            }
        }
        if (!foundEquivalent) {
            oldReports->push_back(new Report(report));
            result = true;
        }
    }
    
    return result;
}
