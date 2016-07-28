
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

#include "Info.h"

void Info::printOptions() {

   std::cout << "\
\
Copyright 2016 Nathan H. Jay\n\n\
Fleece is free software; you can redistribute it and/or modify it under the\n\
terms of the GNU Lesser General Public License as published by the Free\n\
Software Foundation; either version 3.0 of the License, or (at your option)\n\
any later version.\n\n\
This software is distributed in the hope that it will be useful, but WITHOUT\n\
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS\n\
FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more\n\
details.\n\n\
You should have received a copy of the GNU Lesser General Public License\n\
along with this software; if not, see www.gnu.org/licenses\n\n";

   std::cout << "DATA:\n";
   std::cout << "\n  byte_source | ./fleece\n";
   std::cout << "    To pipe bytes from a file or program into fleece\n";

   std::cout << "\n  -n=#\n";
   std::cout << "    To generate a set number of random instructions\n";
   std::cout << "\n  -len=#\n";
   std::cout << "    To specify the number of bytes per instruction. Note: decoders use a number of bytes specific to the instruction or architecture.\n";
   
   std::cout << "\n\nOUTPUT & REPORTING:\n";
   std::cout << "\n  -o=output_filename\n";
   std::cout << "    (MANDATORY) To set the output file.\n";
   std::cout << "\n  -m=matched output filename\n";
   std::cout << "    Outputs matched instructions to this file.\n";
   std::cout << "\n  -t\n";
   std::cout << "    Shows timing information at the end of execution\n";
   std::cout << "\n  -norm\n";
   std::cout << "    Normalizes the output of decoders. (work in progress).\n";
   std::cout << "\n  -bytes\n";
   std::cout << "    Prints the raw bytes of an instruction.\n";
   std::cout << "\n  -show\n";
   std::cout << "    Prints the results of each decoding to stdout.\n";

   std::cout << "\n\nOPTIONS:\n";
   std::cout << "\n  -arch=\n";
   std::cout << "    (MANDATORY) x84_64 or Aarch64\n";
   std::cout << "\n  -decoders=decoder1,decoder2\n";
   std::cout << "    (MANDATORY) choose from: xed, dyninst, llvm, gnu\n\n";
}

void Info::printVersion() {
   std::cout << "Hah! Like there's a version number or something...\n";
}
