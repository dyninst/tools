
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

#include "Options.h"
#include "Mystring.h"
#include "MappedInst.h"
#include "Decoders.h"
#include "Hashcounter.h"
#include "Info.h"
#include "Alias.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <ios>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <fstream>

#define BUFFER_SIZE 1024

void removeErrors(char*);

int main(int argc, char** argv) {

   if (argc < 2) {
      std::cout << "Error: no input file\n";
      return 0;
   }

   removeErrors(argv[1]);
}
/*
 * This function is used to cross-check the error reporting of multiple
 * decoders. The list below is all tokens which suggest that an error has
 * occured during the decoding process. Every entry is checked for every
 * decoder used during reporting.
 */
bool signalsError(char* token) {
   return (
      !strcmp(token, "No_Entry")        ||
      !strcmp(token, "[INVALID]")       ||
      !strcmp(token, "[<invalid_reg>]") ||
      !strcmp(token, "<invalid_reg>,")  ||
      !strcmp(token, "<invalid_reg>")   ||
      !strcmp(token, "<INVALID_REG>")   ||
      !strcmp(token, "nop")             ||
      !strcmp(token, "bad")             ||
      !strcmp(token, "?")               ||
      !strcmp(token, "?,")              ||
      !strcmp(token, "undefined")       ||
      !strcmp(token, "undefined,")      ||
      !strcmp(token, "nyi")             ||
      !strcmp(token, "INVALID")         ||
      !strcmp(token, "invalid")
   );
}

/*
 * Determines whether or not the decodings are equivalent.
 */
bool hasDecodingError(char* decodedInsn) {

   TokenList tList(decodedInsn);

   bool err = false;
   for (unsigned int i = 0; !err && i < tList.size(); i++) {
      err = signalsError(tList.getToken(i));
   }

   return err;
}

void removeErrors(char* filename) {

   char* str1 = (char*)malloc(BUFFER_SIZE);
   char* str2 = (char*)malloc(BUFFER_SIZE);

   std::string line;
   std::ifstream infile(filename);
   while (std::getline(infile, line)) {

      char* s1 = str1;
      char* s2 = str2;

      const char* cur = line.c_str();
      while (*cur && *cur != ';' && s1 < str1 + BUFFER_SIZE - 1) {
         *s1 = *cur;
         cur++;
         s1++;
      }
      *s1 = 0;

      if (*cur == ';') {
         cur += 2;
      }

      while (*cur && *cur != ';' && s2 < str2 + BUFFER_SIZE - 1) {
         *s2 = *cur;
         cur++;
         s2++;
      }
      *s2 = 0;
     
      if (*str2) {
         if (!hasDecodingError(str1) && !hasDecodingError(str2)) {
            std::cout << str1 << "; " << str2 << cur << "\n";
         }
      }
   
   }

   infile.close();
}

