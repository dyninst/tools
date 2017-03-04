
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

#ifndef FIND_LIST_H
#define FIND_LIST_H

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

/*
 * An FLEntry is an entry into a FindList. Whenever the substring "str" is
 * found within a string being searched, the provided function will be called
 * with the provided void* argument.
 * 
 * str: The substring that should be located within a longer string.
 * func: The function that should be called. It will be passed:
 *     char* buf:  a pointer to the start of the located substring.
 *     int len:    the length of the string str.
 *     int bufLen: the length of the buffer, starting at the start of the
 *         located substring.
 *     void* arg:  an argument provided to the function that runs on the
 *         located substring.
 */
typedef struct FLEntry {
    char* str;
    int len;
    void (*func)(char* buf, int bufLen, void* arg);
    void* arg;
} FLEntry;

/*
 * A FindList is a structure that locates all substrings in a larger string in
 * O(n * m) time on average where n is the length of the string being searched
 * and m is the maximum length of all substrings being searched for.
 */
class FindList {
public:

    /*
     * Allocates size entries in the FindList. Because the FindList uses a
     * hashtable to match with substrings, this value should be much higher
     * (about three times higher) than the expected number of entries in order
     * to obtain the O(n * m) average time search with high probability.
     */
    FindList(uint32_t size);
    
    /*
     * Destroys a FindList object, freeing all of its terms. This does NOT
     * free any of the void* args in the FLEntry objects. If those values
     * contain memory that must be freed, they will need to be freed by the
     * creator.
     */
    ~FindList();

    /*
     * Adds a term to the find list. Whenever a string is searched, if the
     * substring val exists in that string, then the function func will
     * be called with the start of val, the remaining length of the buffer
     * and the void* arg given here.
     *
     * Args:
     *   val: The substring whose discovery should result in a call to func.
     *   func: The function called whenever val is discovered in a string.
     *   funcArg: The final arguement to func whenever val is found.
     *
     * Notes: The behavior of a FindList is undefined if two different terms 
     * contain the same val. The strings are searched linearly, once, so any
     * changes made by a FindList that result in the presense of a string with
     * value val occuring prior to the current location (buf) will not be
     * found.
     */
    void AddTerm(const char* val, void (*func)(char* buf, int bufLen, void* arg),
        void* func_arg);

    /*
     * Searches through a buffer and attempts to find all of the terms in this
     * FindList.
     */
    void Process(char* buf, int bufLen);

private:

    /*
     * The number of terms in this FindList.
     */
    uint32_t nTerms;

    /*
     * The size of the hashtable for this FindList. Should be a prme number 
     * around 3x the value of nTerms once the list is filled.
     */
    uint32_t size;
    
    /*
     * The length of the longest term that needs to be searched for.
     */
    int maxStrLen;

    /*
     * The length of the shortest term that needs to be searched for.
     */
    int minStrLen;

    /*
     * An array of FLEntry objects. This array is used as a hashtable that uses
     * rehashing on collision.
     */
    FLEntry* terms;

    /*
     * A simple string hashing function used in the FindList. Do NOT change the
     * implementation of this string hashing function without changing the
     * hashing within the Process function to match.
     */
    uint32_t hash(const char* val);
};

#endif // FIND_LIST_H
