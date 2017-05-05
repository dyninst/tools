#ifndef _ARCHITECTURE_H_
#define _ARCHITECTURE_H_

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include "FieldList.h"
#include "RegisterSet.h"

namespace Architecture {
    extern int maxInsnLen;
    extern std::string name;
    void init(const char* arch);
    bool isReg(const char* str);
    void addRegSet(RegisterSet* regSet);
    void replaceRegSets(FieldList& fl);
    void destroy();
    const char* getOpcode(FieldList& fl);
    extern std::unordered_map<const char*, const char*, StringUtils::str_hash, StringUtils::str_eq> names;
}

#endif /* _ARCHITECTURE_H_ */
