
#include "Report.h"

unsigned long long totalReportIssueTime = 0;

Report::Report(Report* r) : Report(r->asmList) {
}

Report::Report(std::vector<Assembly*>& asmList) {
    
    assert(asmList.size() >= 2);
    
    this->asmList = std::vector<Assembly*>();

    for (auto it = asmList.begin(); it != asmList.end(); ++it) {
        this->asmList.push_back(new Assembly(**it));
    }
}

Report::~Report() {
    for (auto it = asmList.begin(); it != asmList.end(); ++it) {
        delete *it;
    }
}

void Report::issue(FILE* file) {
    struct timespec startTime;
    struct timespec endTime;
    
    clock_gettime(CLOCK_MONOTONIC, &startTime);
    
    for (auto it = asmList.begin(); it != asmList.end(); ++it) {
        Assembly* curAsm = *it;
        fprintf(file, "%s", curAsm->getString());
        if (!curAsm->isError() && curAsm->getAsmResult() == 'E') {
            fprintf(file, ": ERROR: %s", curAsm->getAsmError());
        }
        fprintf(file, ";");
    }
    Assembly* asm1 = *(asmList.begin());
    const char* bytes = asm1->getBytes();
    for (size_t i = 0; i < asm1->getNBytes(); i++) {
        fprintf(file, "%x ", 0xFF & bytes[i]);
    }
    fprintf(file, "\n");
    fflush(file);
    clock_gettime(CLOCK_MONOTONIC, &endTime);
    totalReportIssueTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                  (endTime.tv_nsec - startTime.tv_nsec);

}

bool Report::isEquivalent(Report* r) {
    
    // Equivalent reports must have the same number of decoders used to
    // create them.
    if (r->asmList.size() != asmList.size()) {
        return false;
    }

    auto it1 = asmList.begin();
    auto it2 = r->asmList.begin();

    while (it1 != asmList.end()) {

        const FieldList* baseFields1 = (*it1)->getFields();
        const FieldList* baseFields2 = (*it2)->getFields();

        if (baseFields1->size() != baseFields2->size()) {
            return false;
        }

        auto innerIt1 = it1;
        auto innerIt2 = it2;

        ++innerIt1;
        ++innerIt2;
        while (innerIt1 != asmList.end()) {

            const FieldList* cmpFields1 = (*innerIt1)->getFields();
            const FieldList* cmpFields2 = (*innerIt2)->getFields();

            if (cmpFields1->size() != cmpFields2->size()) {
                return false;
            }

            int numBaseFields = baseFields1->size();
            int numCmpFields = cmpFields1->size();

            int minFields = numCmpFields > numBaseFields ? 
                numBaseFields : numCmpFields;

            for (int f = 0; f < minFields; f++) {
                if (baseFields1->getField(f) == baseFields2->getField(f) &&
                    cmpFields1->getField(f) != cmpFields2->getField(f)) {
                    return false;
                }
            }
            
            ++innerIt1;
            ++innerIt2;
        }

        ++it1;
        ++it2;
    }

    return true;
}

void Report::makeTemplate(char* buf, size_t bufLen) {
    char* cur = buf;
    char* end = buf + bufLen;
    for (size_t j = 0; j < this->size(); ++j) {
     
        strncpy(cur, this->getAsm(j)->getTemplate(), end - cur);

        while (*cur && cur < end) {
            cur++;
        }
     
        if (cur < end) {
            *cur = ';';
            ++cur;
        }

        if (cur < end) {
            *cur = ' ';
            ++cur;
        }
    }

}

void Report::printDebug() {
    std::cout << "-- REPORT DEBUG --\n";
    for (auto it = asmList.begin(); it != asmList.end(); ++it) {
        std::cout << "ASM:\n" << "\n";
        (*it)->printDebug();
        std::cout << "\n";
    }
}
