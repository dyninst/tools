
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

int null_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_norm(char* buf, int bufLen) {
   return;
}

Decoder* dec_null_x86_32 = new Decoder(&null_decode, NULL, &null_norm, "null", "x86_32");
Decoder* dec_null_x86_64 = new Decoder(&null_decode, NULL, &null_norm, "null", "x86_64");
Decoder* dec_null_aarch64 = new Decoder(&null_decode, NULL, &null_norm, "null", "aarch64");
Decoder* dec_null_ppc = new Decoder(&null_decode, NULL, &null_norm, "null", "ppc");
Decoder* dec_null_ppc_32 = new Decoder(&null_decode, NULL, &null_norm, "null", "ppc_32");
Decoder* dec_null_armv6 = new Decoder(&null_decode, NULL, &null_norm, "null", "armv6");
