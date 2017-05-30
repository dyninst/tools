
/*
 * See fleece/COPYRIGHT for copyright information.
 *
 * This file is a part of Fleece.
 *
 * Fleece is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License, or (at your option)
 * any later version.
 *  
 * This software is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, see www.gnu.org/licenses
*/

#ifndef _REGISTER_SET_H_
#define _REGISTER_SET_H_

#include <assert.h>
#include <string.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include "FieldList.h"
#include "StringUtils.h"

/*
 * This class contains a list of register names and generic symbols that can be
 * use to create format strings.
 */
class RegisterSet {
public:

    /*
     * Creates a register set given a format string (which should contain a
     * single %d field for the number) and the bounds for register number.
     */
    static RegisterSet* makeFormattedRegSet(const char* setName, const char* baseName, 
        int lowerBound, int upperBound);
    
    /*
     * Creates an empty register set whose register names will be replaced with
     * the c-string symbol when format strings are created.
     */
    RegisterSet(const char* symbol);

    /*
     * Destroys a RegisterSet, freeing memory.
     */
    ~RegisterSet();

    /*
     * Adds a register name to this set. When this name appears in assembly
     * language, it will be replaced with the generic symbol in a format
     * string.
     */
    void addRegName(const char* regName);
    
    /*
     * Returns true if the c-string passed as an argument is one of the names
     * in this register set.
     */
    bool isReg(const char* str);

    /*
     * Returns the symbol for this register set.
     */
    const char* getSymbol();

    /*
     * Replaces all fields that are register names with the associated
     * generic symbol for that register.
     */
    void replaceRegNamesWithSymbol(FieldList& fl);

    /*
     * Returns a list of all names in this register set. This is used for
     * merging register sets (all names can be taken from one set and added
     * to another with the appropriate generic symbol).
     */
    std::vector<const char*> getNameList() { return nameList; }

private:

    /*
     * The list of all register names in this set.
     */
    std::vector<const char*> nameList;

    /*
     * The generic symbol used for register in this set.
     */
    char* sym;

    /*
     * A mapping from register name to generic symbol.
     */
    std::unordered_map<char*, char*, StringUtils::str_hash, StringUtils::str_eq> names;
};

#endif // _REGISTER_SET_H_
