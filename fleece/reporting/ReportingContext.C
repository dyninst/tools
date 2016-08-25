
#include "ReportingContext.h"

ReportingContext::ReportingContext(FILE* outf) {
  
    // Verify that the files are okay and we can make a record of all
    // differences seen.
    outFile = outf;
    assert(outFile != NULL && "Report file should not be null!");

    diffMap = new std::map<char*, int, StringUtils::str_cmp>();
    assert(diffMap != NULL && "Report hashcounter should not be null!");

    // Initialize summary data to all zeroes.
    nProcessed = 0;
    nMatches = 0;
    nReports = 0;
    nSuppressed = 0;
}

ReportingContext::~ReportingContext() {

    // We only need to delete the difference counter, since the file was passed
    // as an already-opened FILE*, someone else is responsible.
    assert(diffMap != NULL && "Report difference map should not be null!");

    delete diffMap;
}

void ReportingContext::reportDiff(const char** insns, int nInsns, 
        const char* bytes, int nBytes) {
   
    // Print all decoded instructions to the file with a semicolon separating
    // them.
    for (int i = 0; i < nInsns; i++) {
        int rc = fprintf(outFile, "%s; ", insns[i]);
        assert(rc > 0 && "Reporting file write failed!");
    }

    // Print each byte to the file with spaces separating them.
    for (int i = 0; i < nBytes; i++) {
        int rc = fprintf(outFile, "%x ", 0xFF & bytes[i]);
        assert(rc > 0 && "Reporting write failed!");
    }

    // Each report is followed by a newline.
    int rc = fprintf(outFile, "\n");
    assert(rc == 1 && "Reporting write failed!");
}

int ReportingContext::processDecodings(const char** insns, int nInsns, 
        const char* bytes, int nBytes) {
   
    // Update summary data.
    nProcessed++;

    // Check if every instruction matches the first. If they are all equivalent,
    // there is no more processing to do, simply return.
    bool allMatch = true;
    for (int i = 1; allMatch && i < nInsns; i++) {
        allMatch = doesDecodingMatch(insns[0], insns[i]);
    }

    if (allMatch) {
       nMatches++;
       return nBytes;
    }

    // Check if we need to report the difference and do so. Update summary data.
    if (shouldReportDiff(insns, nInsns)) {
        nReports++;
        reportDiff(insns, nInsns, bytes, nBytes);
    } else {
        std::cout << "Suppressed:\n";
        reportDiff(insns, nInsns, bytes, nBytes);
        nSuppressed++;
    }

    return nBytes;
}

void ReportingContext::printSummary(FILE* outf) {
 
    // If the file given to this function is null, write to the file given to
    // the ReportingContext object by default.
    if (outf == NULL) {
        outf = outFile;
    }

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

bool ReportingContext::shouldReportDiff(const char** insns, int nInsns) {

    // Allocate buffers for the instruction templates and output.
    char** insnTemplates = (char**)malloc(nInsns * sizeof(char*));
    char* buf = (char*)malloc(256 * nInsns);
    char* end = buf + 256 * nInsns;
    assert(insnTemplates != NULL && buf != NULL);

    // We're going to convert each instruction to a list of tokens.
    std::vector<TokenList*> tLists;

    int nTokens;
    for (int i = 0; i < nInsns; i++) {
        tLists.push_back(new TokenList(insns[i]));

        // Strip the hex from each list.
        tLists[i]->stripHex();

        // If they all have the same number of tokens, we can try to line the up
        // to see if there are individual differences.
        if (i == 0) {
            nTokens = tLists[i]->size();
        } else {

            // If any isn't equal, set the count to -1, since that will be an
            // error value.
            if (tLists[i]->size() != (size_t)nTokens) {
                nTokens = -1;
            }
        }

        // Leave some room for extra register value.
        int len = tLists[i]->getTotalBytes() + 64;

        insnTemplates[i] = (char*)malloc(len);
        assert(insnTemplates[i] != NULL);

        // Take the stripped token list and make a buffer we can turn into the
        // template by replacing register sets.
        tLists[i]->fillBuf(insnTemplates[i], len);
  
        Architecture::replaceRegSets(insnTemplates[i], len);
    }

    bool result = false;
    // If we still think the difference should be reported, now make a string
    // with all instruction templates.
    for (int j = 0; j < nInsns; j++) {
     
        char* cur = buf;

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
   
    // Free the buffer and templates used and delete the token lists.
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

    TokenList tList1(insn1);
    TokenList tList2(insn2);

    /*
     * First, determine if either of the decoded results produced any tokens
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
     * If the number of tokens in the lists are different, the decodings do not
     * match.
     */
    if (tList1.size() != tList2.size()) {
        return false;
    }

    /*
     * If any of the tokens are NOT aliases of the corresponding token in the
     * other list, then the decodings do not match.
     */
    for (unsigned int i = 0; i < tList1.size(); i++) {
        if (strcmp(tList1.getToken(i), tList2.getToken(i)) &&
             !Alias::isAlias(tList1.getToken(i), tList2.getToken(i))) {
            return false;
        }
    }

    /*
     * If we're here, it means that the decodings have the same number of
     * tokens, and those tokens are either identical, or they are aliases of
     * eachother.
     */
    return true;
}

