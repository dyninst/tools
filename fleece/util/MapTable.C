
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

#include "MapTable.h"

MapTable::MapTable(unsigned int size) {
   this->size = size;
   mapNodes = (MapNode**)malloc(size * sizeof(MapNode*));
   for (unsigned int i = 0; i < size; i++) {
      mapNodes[i] = NULL;
   }
}

// TODO: Implement destructor that walks all buckets and deletes them.
MapTable::~MapTable() {
   std::cerr << "ERROR: METHOD NOT IMPLEMENTED!\n" << std::endl;
   exit(1);
}

void MapTable::add(MappedInst* m) {
   unsigned long bucket = m->getBitTypeHash() % size;
   MapNode* cur = mapNodes[bucket];
   
   while (cur != NULL) {
      if (cur->btmap->addInst(m) == 0 ||
          cur->btmap->contains(m)) {
         return;
      }
      cur = cur->next;
   }

   BitTypeMap* newMap = new BitTypeMap(m);
   MapNode* newNode = new MapNode();
   newNode->btmap = newMap;
   newNode->next = mapNodes[bucket];
   mapNodes[bucket] = newNode;
}

void MapTable::add(BitTypeMap* m) {
   unsigned long bucket = m->getBitTypeHash() % size;
   MapNode* cur = mapNodes[bucket];
   
   while (cur != NULL) {
      if (cur->btmap->combine(m) == 0) {
         return;
      }
      cur = cur->next;
   }

   BitTypeMap* newMap = new BitTypeMap(m);
   MapNode* newNode = new MapNode();
   newNode->btmap = newMap;
   newNode->next = mapNodes[bucket];
   mapNodes[bucket] = newNode;
   
}

unsigned int MapTable::getSize() {
   return size;
}

MapNode** MapTable::getMapNodes() {
   return mapNodes;
}

void MapTable::fuzzDecoders(Decoder* d1, Decoder* d2) {
   for (unsigned int i = 0; i < size; i++) {
      MapNode* cur = mapNodes[i];
      while (cur != NULL) {
         cur->btmap->fuzzDecoders(d1, d2);
         cur = cur->next;
      }
   }
}

std::ostream& operator<<(std::ostream& s, MapTable& m) {
   for (unsigned int i = 0; i < m.getSize(); i++) {
      MapNode* cur = m.getMapNodes()[i];
      while (cur != NULL) {
         s << *(cur->btmap) << std::endl;
         cur = cur->next;
      }
   }
   return s;
}
