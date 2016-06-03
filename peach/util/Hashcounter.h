
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

#ifndef _HASHCOUNTER_H_
#define _HASHCOUNTER_H_

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <cstdlib>

/*
 * Structure used in the chained-buckets structure for a hashtable.
 */
typedef struct Hashpair {

   char* key1;
   char* key2;

   // The value counts the number of times that this pair of keys has appeared
   // toegether, where one decoder produced one of the strings and one
   // assembler produced the other.
   unsigned int value;
   Hashpair* next;

} Hashpair;

/*
 * A wrapper for a simple hashtable where the prupose is to track the number of
 * times that paris of strings have been associated. There are two keys, one
 * for each string. The value is the number of times, including the one
 * currently being incremeneted, that the pair has been observed.
 */
class Hashcounter {

public:

   /*
    * Constructor where the number of slots in the hashtable is specified.
    */
   Hashcounter(unsigned int size);
   
   /*
    * Simple destructor.
    */
   ~Hashcounter();
   
   /*
    * Increments the value associated with these two keys, returning the value
    * stored with the pair AFTER it has been incremented.
    */
   unsigned int increment(const char* key1, const char* key2);

   /*
    * Returns the value associated with the two pairs.
    */
   unsigned int get(const char* key1, const char* key2);


   /*
    * Write to the given output stream every pair of keys and the number of
    * times it has been observed.
    */
   void dump(std::ostream& out);

private:

   /*
    * An array of pointers to the chained buckets of the hashtable. These
    * values will hold null at the index if no value has been set with a key
    * that belongs in that bucket.
    */
   Hashpair** buckets;
   
   /*
    * The number of buckets that can be hashed to.
    */
   unsigned int size;

   /*
    * The number of unique pairs in the hashcounter.
    */
   unsigned int nPairs;

   /*
    * The number of bytes of memory used by this hashcounter.
    */
   unsigned int memSize;

};

#endif // _HASHCOUNTER_H_
