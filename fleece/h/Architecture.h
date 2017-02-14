#ifndef _ARCHITECTURE_H_
#define _ARCHITECTURE_H_

#include <iostream>
#include <string>
#include <vector>
#include "FieldList.h"
#include "RegisterSet.h"

namespace Architecture {
    extern int maxInsnLen;
    extern std::string name;
    void init(const char* arch);
    void replaceRegSets(FieldList& fl);
    void destroy();
    const char* getOpcode(FieldList& fl);
}

#endif /* _ARCHITECTURE_H_ */
