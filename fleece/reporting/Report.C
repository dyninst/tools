
#include "Report.h"

Report::Report(Report* r) {
    this->nInsns = r->nInsns;
    this->nBytes = r->nBytes;

    this->insns = (char**)malloc(nInsns * sizeof(*(this->insns)));
    this->reasmErrors = (char**)malloc(nInsns * sizeof(*(this->reasmErrors)));
    assert(this->insns != NULL);
    for (int i = 0; i < nInsns; i++) {
        this->insns[i] = strdup(r->insns[i]);
        this->reasmErrors[i] = strdup(r->reasmErrors[i]);
    }

    this->bytes = (char*)malloc(nBytes);
    memcpy(this->bytes, r->bytes, nBytes);
}

Report::Report(const char** insns, int nInsns, const char* bytes, int nBytes,
        const char** reasmErrors) {

    this->nInsns = nInsns;
    this->nBytes = nBytes;

    this->insns = (char**)malloc(nInsns * sizeof(*(this->insns)));
    this->reasmErrors = (char**)malloc(nInsns * sizeof(*(this->reasmErrors)));
    assert(this->insns != NULL);
    for (int i = 0; i < nInsns; i++) {
        this->insns[i] = strdup(insns[i]);
        this->reasmErrors[i] = strdup(reasmErrors[i]);
    }

    this->bytes = (char*)malloc(nBytes);
    memcpy(this->bytes, bytes, nBytes);
}

Report::~Report() {
    for (int i = 0; i < nInsns; i++) {
        free(insns[i]);
        free(reasmErrors[i]);
    }
    free(insns);
    free(reasmErrors);
    free(bytes);
}

void Report::issue(const char* filename) {
    FILE* f = fopen(filename, "a+");
    if (f == NULL) {
        std::cerr << "Could not open file: " << filename << "\n";
        std::cerr << "Error was: " << strerror(errno) << "\n";
        exit(-1);
    }
    assert(f != NULL);
    for (int i = 0; i < nInsns; i++) {
        fprintf(f, "%s", insns[i]);
        if (*reasmErrors[i] != '\0') {
            fprintf(f, ": ERROR: %s", reasmErrors[i]);
        }
        fprintf(f, ";");
    }
    for (int i = 0; i < nBytes; i++) {
        fprintf(f, "%x ", 0xFF & bytes[i]);
    }
    fprintf(f, "\n");
    fclose(f);
}

bool Report::isEquivalent(Report* r) {
    if (r->nInsns != nInsns) {
        std::cout << "REPORTS NOT EQUIVALENT!\n";
        return false;
    }

    for (int i = 0; i < nInsns; i++) {
        FieldList oldFields1 = FieldList(getInsn(i));
        FieldList newFields1 = FieldList(r->getInsn(i));
        
        if (oldFields1.size() != newFields1.size()) {
            std::cout << "REPORTS NOT EQUIVALENT!\n";
            return false;
        }

        for (int j = i + 1; j < nInsns; j++) {
            FieldList oldFields2 = FieldList(getInsn(j));
            FieldList newFields2 = FieldList(r->getInsn(j));

            if (oldFields2.size() != newFields2.size()) {
                std::cout << "REPORTS NOT EQUIVALENT!\n";
                return false;
            }

            int minFields = oldFields2.size() > oldFields1.size() ?
                oldFields1.size() : oldFields2.size();

            for (int f = 0; f < minFields; f++) {
                if (oldFields1.getField(f) == oldFields2.getField(f) &&
                    newFields1.getField(f) != newFields2.getField(f)) {

                    std::cout << "REPORTS NOT EQUIVALENT!\n";
                    return false;
                }
            }
            
        }
    }

    return true;
}
