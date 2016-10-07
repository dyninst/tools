
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
   sym = (char*)malloc(strlen(symbol) + 1);
   assert(sym != NULL);
   strcpy(sym, symbol);
}

RegisterSet::~RegisterSet() {
   
   while(!regNames.empty()) {
      char* regName = regNames.back();
      regNames.pop_back();
      free(regName);
   }

   free(sym);
}

void RegisterSet::addRegName(const char* regName) {
   char* newName = (char*)malloc(strlen(regName) + 1);
   assert(newName != NULL);
   strcpy(newName, regName);

   regNames.push_back(newName);
}
   
void RegisterSet::replaceRegNamesWithSymbol(FieldList& fl) {
    for (unsigned int i = 0; i < fl.size(); i++) {
        bool replaced = false;
        for (size_t j = 0; !replaced && j < regNames.size(); j++) {
            size_t nameLen = strlen(regNames[j]);
            const char* field = fl.getField(i);
            if (!strncmp(field, regNames[j], nameLen)) {
                if (strlen(field) == nameLen) {
                    fl.setField(i, sym);
                    replaced = true;
                } else if (field[nameLen] == '.') {
                    int fieldLen = strlen(field);
                    char newField[fieldLen - nameLen + strlen(sym)];
                    snprintf(newField, fieldLen - nameLen + strlen(sym), 
                            "%s%s", sym, (field + nameLen));
                    fl.setField(i, strdup(newField));
                    replaced = true;
                }
            }
        }
    }
}
