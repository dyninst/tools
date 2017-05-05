
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

#include "RegisterSet.h"

RegisterSet::RegisterSet(const char* symbol) {
   sym = new char[strlen(symbol) + 1];
   strcpy(sym, symbol);
}

RegisterSet::~RegisterSet() {
   
    for (auto it = names.begin(); it != names.end(); ++it) {
        delete [] (*it).first;
    }

   delete [] sym;
}

void RegisterSet::addRegName(const char* regName) {
    size_t len = strlen(regName) + 1;
    char* name = new char[len];
    strncpy(name, regName, len);

    names.insert(std::make_pair(name, sym));
    nameList.push_back(name);
}

bool RegisterSet::isReg(const char* str) {
    return (names.find((char*)str) != names.end());
}

const char* RegisterSet::getSymbol() {
    return sym;
}
   
void RegisterSet::replaceRegNamesWithSymbol(FieldList& fl) {
    for (unsigned int i = 0; i < fl.size(); i++) {
        auto name = names.find((char*)fl.getField(i));
        if (name != names.end()) {
            fl.setField(i, name->second);
        }       
    }
}
