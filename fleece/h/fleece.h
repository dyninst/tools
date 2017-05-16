/**
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

#ifndef _FLEECE_H_
#define _FLEECE_H_

#include <fstream>
#include <iomanip>
#include <iostream>
#include <ios>
#include <map>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include "BitTypes.h"
#include "Decoder.h"
#include "Info.h"
#include "Mask.h"
#include "MappedInst.h"
#include "Options.h"
#include "ReportingContext.h"
#include "StringUtils.h"

#define DECODED_BUFFER_LEN 256
#define FLUSH_FREQ 100
#define DIR_ACCESS_PERMS S_IRUSR | S_IWUSR | S_IXUSR

#define DEBUG_TIME

#define FLEECE_VERSION_MAJOR 1
#define FLEECE_VERSION_MINOR 0
#define FLEECE_VERSION_BUILD 0
#define FLEECE_VERSION_STRING "1.0.0"

#endif
