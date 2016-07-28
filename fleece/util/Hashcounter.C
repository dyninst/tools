
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

#include "Hashcounter.h"

unsigned long hash(const char* key) {
   unsigned long result = 1;
   unsigned long factor = 31;
   while (*key) {
      result += (*key) * factor;
      factor *= 31;
      key++;
   }
   return result;
}

Hashcounter::Hashcounter(unsigned int size) {
   this->size = size;
   nPairs = 0;
   this->buckets = (Hashpair**)malloc(size * sizeof(Hashpair*));
   this->memSize = size * sizeof(Hashpair*);
   if (buckets == NULL) {
      throw "ERROR: malloc failed\n";
   }
   for (unsigned int i = 0; i < size; i++) {
      buckets[i] = NULL;
   }
}

Hashcounter::~Hashcounter() {
   for (unsigned int i = 0; i < this->size; i++) {
      Hashpair* cur = buckets[i];
      while (cur != NULL) {
         Hashpair* next = cur->next;
         free(cur);
         cur = next;
      }
   }
   free(buckets);
}

unsigned int Hashcounter::increment(const char* key1, const char* key2) {
   unsigned int index = (hash(key1) * hash(key2)) % size;
   Hashpair* bucket = buckets[index];
   Hashpair* cur = bucket;
   static int maxHCLevel = 0;
   int maxLevel = 0;
   while (cur != NULL) {

      // Check if the two keys match (in either order).
      if ((!strcmp(key1, cur->key1) && !strcmp(key2, cur->key2)) ||
          (!strcmp(key1, cur->key2) && !strcmp(key2, cur->key1))) {

          // We have found the proper element.
          cur->value++;
          return cur->value;
      }
      cur = cur->next;
      maxLevel++;
   }

   maxLevel++;
   if (maxLevel > maxHCLevel) {
      maxHCLevel = maxLevel;
      std::cerr << "Hashcounter depth: " << maxHCLevel << "\n";
   }
   // We couldn't find the element we wanted, so let's make it.
   cur = (Hashpair*)malloc(sizeof(Hashpair));
   size_t len1 = strlen(key1);
   size_t len2 = strlen(key2);
   char* newKey1 = (char*)malloc(len1 + 1);
   char* newKey2 = (char*)malloc(len2 + 1);
   memSize += sizeof(Hashpair) + 2 + len1 + len2;
   
   if (cur == NULL || newKey1 == NULL || newKey2 == NULL) {
      throw "ERROR: malloc failed\n";
   }
   
   strcpy(newKey1, key1);
   strcpy(newKey2, key2);
   newKey1[len1] = 0;
   newKey2[len2] = 0;

   cur->key1 = newKey1;
   cur->key2 = newKey2;
   cur->value = 1;

   // Put this value into the chain for this bucket.
   cur->next = bucket;
   buckets[index] = cur;
   
   nPairs++;
   
   return 1;
}


unsigned int Hashcounter::get(const char* key1, const char* key2) {
   unsigned int index = (hash(key1) * hash(key2)) % size;
   Hashpair* bucket = buckets[index];
   Hashpair* cur = bucket;
   while (cur != NULL) {

      // Check if the two keys match (in either order).
      if ((!strcmp(key1, cur->key1) && !strcmp(key2, cur->key2)) ||
          (!strcmp(key1, cur->key2) && !strcmp(key2, cur->key1))) {

          // We have found the proper element.
          cur->value++;
          return cur->value;
      }
      cur = cur->next;
   }

   return 0;
}


int compare(const void* p1, const void* p2) {
   return ((Hashpair*)p1)->value - ((Hashpair*)p2)->value;
}


void Hashcounter::dump(std::ostream& out) {
 
   bool found = true;

   Hashpair** arr = (Hashpair**)malloc(nPairs * sizeof(Hashpair*));
   unsigned int index = 0;

   for (unsigned int i = 0; i < size; i++) {
      Hashpair* cur = buckets[i];

      while (cur != NULL) {
         
         arr[index] = cur;
         
         cur = cur->next;
         index++;
      }
   }

   std::cout << "qsort\n";
   qsort(arr, nPairs, sizeof(Hashpair*), &compare);
   std::cout << "post qsort\n";
   
   for (unsigned int i = 0; i < nPairs; i++) {
      if (arr[i] == NULL) {
         std::cout << "NULL!\n";
      }
      out << arr[i]->key1 << " to " << arr[i]->key2 << " (" << arr[i]->value << ") " << std::endl;
   }

   free(arr);

}

