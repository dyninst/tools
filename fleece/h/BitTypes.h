
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

#ifndef _BIT_TYPES_H_
#define _BIT_TYPES_H_

#define BIT_TYPE_SWITCH -3
#define BIT_TYPE_CAUSED_ERROR -2
#define BIT_TYPE_UNUSED -1

#define INST_LEN 15

typedef int BitType;

unsigned long hashBitTypes(BitType* bitTypes, unsigned int nBits);

#endif /* _BIT_TYPES_H_ */
