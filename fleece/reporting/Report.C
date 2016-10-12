
#include "Report.h"

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
