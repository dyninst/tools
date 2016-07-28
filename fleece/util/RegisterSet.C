
/*
 * See peach/COPYRIGHT for copyright information.
 *
 * This file is a part of Peach.
 *
 * Peach is free software; you can redistribute it and/or modify it under the
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
   
void RegisterSet::replaceRegNamesWithSymbol(char* buf, int bufLen) {
   
   std::string str(buf);
   for (int i = 0; i < regNames.size(); i++) {

      size_t pos = 0;
      
      int len = strlen(regNames[i]);

      while ((pos = str.find(regNames[i], pos)) != std::string::npos) {
         str.replace(pos, len, sym);
         pos += strlen(sym);
      }

   }

   strncpy(buf, str.c_str(), bufLen);
   buf[bufLen - 1] = 0;
   
}
