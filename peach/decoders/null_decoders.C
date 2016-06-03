
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

int null_aarch64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_aarch64_norm(char* buf, int bufLen) {
   return;
}

int null_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   return -1;
}

void null_x86_64_norm(char* buf, int bufLen) {
   return;
}
