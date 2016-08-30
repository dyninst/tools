
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

#ifndef _AARCH64_COMMON_H_
#define _AARCH64_COMMON_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "StringUtils.h"

void negCond(char* dest, char* src);
void aliasIns(char* buf, int bufLen);
void aliasMovn(char* buf, int bufLen);
void aliasMovz(char* buf, int bufLen);
void aliasCsInsns(char* buf, int bufLen);
void removeExtraZeroesFromFmovImm(char* buf, int bufLen);

#endif // _AARCH64_COMMON_H_
