
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

#include "Options.h"

int    Options::argc = 0;
char** Options::argv = NULL;

void Options::parse(int argc, char** argv) {
   Options::argc = argc;
   Options::argv = (char**)malloc(argc * sizeof(char*));
   for (int i = 0; i < argc; i++) {
      Options::argv[i] = (char*)malloc(strlen(argv[i]) + 1);
      strcpy(Options::argv[i], argv[i]);
   }
}

char* Options::get(const char* str) {

   for (int i = 0; i < argc; i++) {
      char* arg = argv[i];
      const char* tmp = str;

      while (*tmp && *tmp == *arg) {
         tmp++;
         arg++;
      }

      if (!*tmp) {
         return arg;
      }
   }

   return NULL;
}
