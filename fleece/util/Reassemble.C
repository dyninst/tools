
#include "Reassemble.h"
#include "ReassemblyDaemon.h"
#include <iostream>
#include <iomanip>
#include <libelf.h>
#include <err.h>
#include <fcntl.h>
#include <spawn.h>

ReassemblyDaemon* Reassembly::daemon;

int initReasmDaemon() {
    const char* as = Options::get("-as=");
    if (as == NULL) {
        std::cout << "Error: Must specify assembler using \"-as=/path/to/assembler\"\n";
        exit(-1);
    }
    Reassembly::daemon = new ReassemblyDaemon(as);
    Reassembly::daemon->start();
    return 0;
}

char reassemble(const char* bytes, int nBytes, const char* str, 
        char* byteBuf, int bufLen, int* outputLen,
        char* errorBuf, int errorBufLen) {

    static int initResult = initReasmDaemon();

    // Start timing for the reassembly portion of the code.
    int result = Reassembly::daemon->reassemble(str, errorBuf, errorBufLen);
    if (result != 0) {
        return 'E';
    }

    *outputLen = readReassembledBytes(Reassembly::daemon->getOutputFilename(), byteBuf, bufLen);
    if (*outputLen > nBytes || memcmp(byteBuf, bytes, *outputLen)) {
        return 'D';
    }
    return 'S';
}

int readReassembledBytes(const char* filename, char* outBytes, int bufLen) {
    int fd;           // File descriptor for the executable ELF file
    char *sectionName;
    size_t shstrndx;

    Elf* e;           // ELF struct
    Elf_Scn* scn;     // Section index struct
    Elf64_Shdr* shdr; // Section struct
    
    if ((fd = open(filename, O_RDONLY, 0)) < 0) {
        std::cerr << "Could not read bytes from file: " << filename << "\n";
        exit(-1);
    }

    if (elf_version(EV_CURRENT)==EV_NONE) {
        std::cerr << "Incorrect elf version!\n";
        exit(-1);
    }

    if ((e = elf_begin(fd, ELF_C_READ, NULL))==NULL) {
        std::cerr << "Elf could not being reading file: " << filename << "\n";
        exit(-1);
    }

    // Retrieve the section index of the ELF section containing the string table of section names
    if (elf_getshdrstrndx(e, &shstrndx)!=0) {
        std::cerr << "Elf error getting section names\n";
        exit(-1);
    }

    scn = NULL;

    int codeSize = 0;
    // Loop over all sections in the ELF object
    while((scn = elf_nextscn(e, scn)) != NULL) {
    
        // Try to read the next section header
        if ((shdr = elf64_getshdr(scn)) != shdr) {
            std::cerr << "Error reading section header\n";
            exit(-1);    
        }

        // Retrieve the name of the section name
        if ((sectionName = elf_strptr(e, shstrndx, shdr->sh_name)) == NULL) {
            std::cerr << "Error getting section name\n";
            exit(-1);    
        }

        // We need the .text section for the code bytes.
        if (!strcmp(sectionName, ".text")) {

            // We can use the section adress as a pointer, since it corresponds to the actual
            //adress where the section is placed in the virtual memory
            //struct data_t * codeBytes = (struct data_t *) shdr->sh_addr;
            codeSize = shdr->sh_size;
            size_t codeOffset = shdr->sh_offset;

            // Verify the size of the reassembly buffer;
            assert(shdr->sh_size <= (size_t)bufLen && "ERROR: reassembly byte buffer is too small");
            
            // We no longer need the elf object because we found the code.
            elf_end(e);

            // Seek to the file and read the number of bytes expected.
            lseek(fd, codeOffset, SEEK_SET);
            if (read(fd, outBytes, codeSize) != codeSize) {
                std::cerr << "ERROR: Could not read text section of " << filename << "\n";
                exit(-1);
            }

            // Close the file descriptor.
            close(fd);
            return codeSize;
        }
    }

    elf_end(e);
    close(fd);
    return codeSize;
}
