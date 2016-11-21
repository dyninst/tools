
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

#include "InstructionDecoder.h"
#include "StringUtils.h"
#include <string>
#include <iomanip>

using namespace Dyninst;
using namespace InstructionAPI;

void dyninst_x86_64_norm(char* buf, int bufLen) {
   char* cur = buf;
   char* replace = buf;
   bool inSpace = true;
   while (*cur) {
      if (isspace(*cur)) {
         if (!inSpace) {
            inSpace = true;
            *replace = ' ';
            replace++;
         }
      } else {
         inSpace = false;
         if (isupper(*cur)) {
            *replace = *cur + 32 ;
         } else {
            *replace = *cur;
         }
         replace++;
      }
      cur++;
   }
   *replace = *cur;
 
}

int dyninst_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {

   InstructionDecoder d(inst, nBytes, Arch_x86_64);
   Instruction::Ptr p = d.decode();
   strncpy(buf, p->format().c_str(), bufLen);
   return 0;
}
