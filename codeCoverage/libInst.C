/*
 * The instrumentation library for the codeCoverage tool. Provides
 * functions for initialization, registering functions and basic
 * blocks for coverage tracking, and outputting the results.
 */

#include<cstdlib>
#include<cstdio>
#include<iostream>
#include<cstring>
#include<vector>
#include<algorithm>
using namespace std;

class bbRecord {
public:
  string funcName;
  string modName;
  unsigned long address;
  unsigned long count;
  bbRecord() : funcName(""), modName(""), address(0), count(0) {}
};

class funcRecord {
public:
    string funcName;
    string modName;
    unsigned long count;
    funcRecord() : funcName(""), modName(""), count(0) {}
};


// Used to records via qsort
static int compareFuncRecordByName(const void *left, const void *right) {
    funcRecord *leftRecord = (funcRecord *)left;
    funcRecord *rightRecord = (funcRecord *)right;

    return leftRecord->funcName.compare(rightRecord->funcName);
}

static int compareFuncRecordByCount(const void *left, const void *right) {
    funcRecord *leftRecord = (funcRecord *)left;
    funcRecord *rightRecord = (funcRecord *)right;

    if( leftRecord->count < rightRecord->count ) return 1;

    if( leftRecord->count > rightRecord->count ) return -1;

    return 0;
}

static int compareBBRecordByName(const void *left, const void *right) {
    bbRecord *leftRecord = (bbRecord *)left;
    bbRecord *rightRecord = (bbRecord *)right;

    return leftRecord->funcName.compare(rightRecord->funcName);
}

static int compareBBRecordByCount(const void *left, const void *right) {
    bbRecord *leftRecord = (bbRecord *)left;
    bbRecord *rightRecord = (bbRecord *)right;

    if( leftRecord->count < rightRecord->count ) return 1;

    if( leftRecord->count > rightRecord->count ) return -1;

    return 0;
}

// For efficency in instrumentation, indexed by id
static bbRecord *bbs;
static funcRecord *funcs;

int numFuncs = 0;
int numBBs = 0;
int enabled = 0;

// Allocates space for all tracked functions and basic blocks
void initCoverage(int totalFuncs, int totalBBs) {
    numFuncs = totalFuncs;
    numBBs = totalBBs;

    funcs = new funcRecord[numFuncs];
    bbs = new bbRecord[numBBs];

    enabled = 1;
}

// Populates a record for a function
void registerFunc(int id, char *name, char *modName) {
    if( !enabled ) return;

    funcs[id].funcName = name;
    funcs[id].modName = modName;
    funcs[id].count = 0;
}

// Populates a record for a basic block
void registerBB(int id, char *name, char *modName, unsigned long addr) {
    if( !enabled ) return;

    bbs[id].funcName = name;
    bbs[id].modName = modName;
    bbs[id].address = addr;
    bbs[id].count = 0;
}

// Should be called on function entry 
void incFuncCoverage(int id) {
  if( !enabled ) return;

  funcs[id].count++;
}

// Should be called on basic block entry
void incBBCoverage(int id) {
  if( !enabled ) return;

  bbs[id].count++;
}

// Prints the code coverage stats. to standard out, also disables any more tracking
void exitCoverage(int printAll, int printBasicBlocks, int sortAlphabetical) {
  if( !enabled ) return;

  printf("\n\n ************************** Code Coverage ************************* \n\n");
  int count = 0;
  if( sortAlphabetical ) qsort(funcs, numFuncs, sizeof(funcRecord), &compareFuncRecordByName);
  else qsort(funcs, numFuncs, sizeof(funcRecord), &compareFuncRecordByCount);

  for(int i = 0; i < numFuncs; ++i) {
      if( funcs[i].count > 0 ) count++;
      if( printAll || (funcs[i].count > 0) )
        printf(" %4lu : %s, %s\n", funcs[i].count, funcs[i].funcName.c_str(), funcs[i].modName.c_str()); 
  }
  printf("\n ************** Code Coverage %d out of %d functions ************** \n\n", count, numFuncs);

  if (printBasicBlocks) {
    int bbCount = 0;
    printf("\n\n ************************** Basic Block Coverage ************************* \n\n");
    if( sortAlphabetical ) qsort(bbs, numBBs, sizeof(bbRecord), &compareBBRecordByName);
    else qsort(bbs, numBBs, sizeof(bbRecord), &compareBBRecordByCount);

    string curFunc;
    string curMod;
    for(int i = 0; i < numBBs; ++i) {
        if( bbs[i].count > 0 ) bbCount++;
        else if( !printAll ) continue;

        if( curFunc != bbs[i].funcName || curMod != bbs[i].modName ) {
            curFunc = bbs[i].funcName;
            curMod = bbs[i].modName;
            printf(" (%s, %s)\n", bbs[i].funcName.c_str(), bbs[i].modName.c_str());
            printf(" \t %4lu : 0x%-8lx\n", bbs[i].count, bbs[i].address);
        }else{
            printf(" \t %4lu : 0x%-8lx\n", bbs[i].count, bbs[i].address);
        }

    }
    printf("\n ************** Basic Block Coverage %d out of %d blocks ************** \n\n", bbCount, numBBs);
  }

  enabled = 0;
}
