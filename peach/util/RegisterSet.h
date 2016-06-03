
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

#ifndef _REGISTER_SET_H_
#define _REGISTER_SET_H_

#include <assert.h>
#include <string.h>
#include <iostream>
#include <vector>

class RegisterSet {
public:
   RegisterSet(const char* symbol);
   ~RegisterSet();
   void addRegName(const char* regName);
   void replaceRegNamesWithSymbol(char* buf, int bufLen);
private:
   char* sym;
   std::vector<char*> regNames;
};

#endif // _REGISTER_SET_H_
