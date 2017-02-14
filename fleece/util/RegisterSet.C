
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

    /*
    while(!regNames.empty()) {
       char* regName = regNames.back();
       regNames.pop_back();
       free(regName);
    }
    */

   delete [] sym;
}

void RegisterSet::addRegName(const char* regName) {
    /*
    char* newName = (char*)malloc(strlen(regName) + 1);
    regNames.push_back(newName);
    */
    size_t len = strlen(regName) + 1;
    char* name = new char[len];
    strncpy(name, regName, len);

    names.insert(std::make_pair(name, sym));
}
   
void RegisterSet::replaceRegNamesWithSymbol(FieldList& fl) {
    for (unsigned int i = 0; i < fl.size(); i++) {
        auto name = names.find((char*)fl.getField(i));
        if (name != names.end()) {
            fl.setField(i, name->second);
            /*
            size_t nameLen = strlen(name.first);
            if (strlen(field) == nameLen) {
                fl.setField(i, sym);
            } else if (field[nameLen] == '.') {
                int fieldLen = strlen(field);
                char newField[fieldLen - nameLen + strlen(sym)];
                snprintf(newField, fieldLen - nameLen + strlen(sym), 
                        "%s%s", sym, (field + nameLen));
                fl.setField(i, newField);
                replaced = true;
            }
            */
        }       

        /*
        for (size_t j = 0; !replaced && j < regNames.size(); j++) {
            const char* field = fl.getField(i);
            if (!strncmp(field, regNames[j], nameLen)) {
            }
        }
        */
    }
}
