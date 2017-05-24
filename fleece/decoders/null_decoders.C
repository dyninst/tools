
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

#include "Decoder.h"

int null_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_aarch64_norm(char* buf, int bufLen) {
   return;
}

int null_x86_32_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_x86_32_norm(char* buf, int bufLen) {
   return;
}

int null_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_x86_64_norm(char* buf, int bufLen) {
   return;
}

int null_ppc_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_ppc_norm(char* buf, int bufLen) {
   return;
}

Decoder* dec_null_x86_32 = new Decoder(&null_x86_32_decode, NULL, &null_x86_32_norm, "null", "x86_32");
Decoder* dec_null_x86_64 = new Decoder(&null_x86_64_decode, NULL, &null_x86_64_norm, "null", "x86_64");
Decoder* dec_null_aarch64 = new Decoder(&null_aarch64_decode, NULL, &null_aarch64_norm, "null", "aarch64");
Decoder* dec_null_ppc = new Decoder(&null_ppc_decode, NULL, &null_ppc_norm, "null", "ppc");
