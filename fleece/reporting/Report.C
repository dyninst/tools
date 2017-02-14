
#include "Report.h"

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

void Report::issue(const char* filename) {
    FILE* f = fopen(filename, "a+");
    if (f == NULL) {
        std::cerr << "Could not open file: " << filename << "\n";
        std::cerr << "Error was: " << strerror(errno) << "\n";
        exit(-1);
    }
    assert(f != NULL);
    assert(asmList.size() >= 2);
    for (auto it = asmList.begin(); it != asmList.end(); ++it) {
        Assembly* curAsm = *it;
        fprintf(f, "%s", curAsm->getString());
        if (!curAsm->isError() && curAsm->getAsmResult() == 'E') {
            fprintf(f, ": ERROR: %s", curAsm->getAsmError());
        }
        fprintf(f, ";");
    }
    Assembly* asm1 = *(asmList.begin());
    const char* bytes = asm1->getBytes();
    for (size_t i = 0; i < asm1->getNBytes(); i++) {
        fprintf(f, "%x ", 0xFF & bytes[i]);
    }
    fprintf(f, "\n");
    fclose(f);
}

bool Report::isEquivalent(Report* r) {
    if (r->asmList.size() != asmList.size()) {
        std::cout << "first:\n";
        for (auto it = asmList.begin(); it != asmList.end();
        ++it) {
            std::cout << (*it)->getString() << "\n";
        }
        std::cout << "second:\n";
        for (auto it = r->asmList.begin(); it != r->asmList.end();
        ++it) {
            std::cout << (*it)->getString() << "\n";
        }
        std::cout << "REPORTS NOT EQUIVALENT!\n";
        exit(-1);
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

void Report::printDebug() {
    std::cout << "-- REPORT DEBUG --\n";
    for (auto it = asmList.begin(); it != asmList.end(); ++it) {
        std::cout << "ASM:\n" << "\n";
        (*it)->printDebug();
        std::cout << "\n";
    }
}
