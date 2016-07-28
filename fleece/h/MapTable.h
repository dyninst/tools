
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

#ifndef _MAP_TABLE_H_
#define _MAP_TABLE_H_

#include <iostream>
#include "BitTypeMap.h"
#include "MappedInst.h"

typedef struct MapNode {
   BitTypeMap* btmap;
   MapNode* next;
} MapNode;

class MapTable {
public:
   MapTable(unsigned int size);
   ~MapTable(void);
   void add(MappedInst* m);
   void add(BitTypeMap* m);
   unsigned int getSize(void);
   MapNode** getMapNodes(void);
   void fuzzDecoders(Decoder* d1, Decoder* d2);
private:
   unsigned int size;
   MapNode** mapNodes;
};

std::ostream& operator<<(std::ostream& s, MapTable& m);

#endif // _MAP_TABLE_H_
