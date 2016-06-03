
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

#include "ReportingContext.h"
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

int main(int argc, char** argv) {

   if (argc < 2) {
      std::cout << "Error: no input files\n";
      return 0;
   }

   char** arg = argv + 1;
   while (*arg != NULL) {
      combineReports(*arg);
      arg++;
   }
}

void combineReports(char* filename) {

   static ReportingContext repContext(stdout);

   char* str1 = (char*)malloc(BUFFER_SIZE);
   char* str2 = (char*)malloc(BUFFER_SIZE);

   char** decBufs = (char**)malloc(2 * sizeof(char*));
   decBufs[0] = str1;
   decBufs[1] = str2;

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
         repContext.processDecodings(decBufs, 2, "", 0);
      }
   
   }

   infile.close();
}
