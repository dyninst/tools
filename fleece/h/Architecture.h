#ifndef _ARCHITECTURE_H_
#define _ARCHITECTURE_H_

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include "FieldList.h"
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
namespace Architecture {

    /*
     * The maximum length of instructions for this architecture, in bytes.
     */
    extern int maxInsnLen;

    /*
     * The name of this architecture as a string. This will be 
     */
    extern std::string name;
    
    /*
     * Initializes the architecture based on the provided architecture name.
     */
    void init(const char* arch);

    /*
     * Adds a register set to this architecture. The registers in this set will
     * be added to the Architecture::names map, which will map register names
     * to generic symbols for quick lookup when format strings are created.
     */
    void addRegSet(RegisterSet* regSet);

    /*
     * Replaces all register fields in the field list with the generic name
     * for each register's set.
     */
    void replaceRegSets(FieldList& fl);

    /*
     * Frees the resources used by this namespace.
     */
    void destroy();

    /*
     * A mapping from register name to generic symbol.
     */
    extern std::unordered_map<const char*, const char*, StringUtils::str_hash, StringUtils::str_eq> regSymbolMap;
}

#endif /* _ARCHITECTURE_H_ */
