#ifndef _ARCHITECTURE_H_
#define _ARCHITECTURE_H_

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include "FieldList.h"
#include "Options.h"
#include "RegisterSet.h"

/*
 * The Architecture name space is used to contain the following information
 * about the current architecture of decoders being tested:
 *  - The maximum length of a single instruction in bytes
 *  - The name of the architecture as a string
 *      Options are: x86_64, x86_32, aarch64, armv6, ppc, ppc_32
 *  - A mapping of register names to generic symbols for that register set
 *
 * The function Architecture::init() must be called with one of the
 * architecture names before any other parts of the namespace are used.
 */
class Architecture {
public:
    /*
     * Accessors for information regarding the chosen architecture for this run
     * of Fleece.
     */
    static int getMaxInsnLen() { return currentArch->maxInsnLen; }
    static std::string getName() { return currentArch->name; }
    
    /*
     * Initializes the architecture based on the provided architecture name.
     */
    static void init(const char* arch);

    /*
     * Adds a register set to this architecture. The registers in this set will
     * be added to the Architecture::names map, which will map register names
     * to generic symbols for quick lookup when format strings are created.
     */
    static void addRegSet(RegisterSet* regSet);

    /*
     * Replaces all register fields in the field list with the generic name
     * for each register's set.
     */
    static void replaceRegSets(FieldList& fl);

    /*
     * 
     */
    static void applyArchitectureSpecificNormalization(char* buf, int bufLen);

    Architecture(const char* name, int maxInsnLen, bool (*initFunc)(void), 
        void (*normFunc)(char*, int));
    

private:

    static Architecture* currentArch;

    /*
     * The maximum length of instructions for this architecture, in bytes.
     */
    int maxInsnLen;

    /*
     * The name of this architecture as a string.
     */
    const char* name;

    /*
     * The initialization function that will be called if this architecture is
     * chosen.
     */
    bool (*initFunc)(void);

    /*
     * A mapping from register name to generic symbol.
     */
    std::unordered_map<const char*, const char*, StringUtils::str_hash, StringUtils::str_eq> regSymbolMap;

    /*
     * The normalization function called for architecture specific normalization.
     */
    void (*normFunc)(char*, int);
    
    static std::unordered_map<const char*, Architecture*, StringUtils::str_hash, StringUtils::str_eq>
        architectures;

};

#endif /* _ARCHITECTURE_H_ */
