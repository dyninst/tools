#ifndef _ARCHITECTURE_H_
#define _ARCHITECTURE_H_

#include <string>
#include "Alias.h"
#include "RegisterSet.h"

namespace Architecture {
   extern std::string name;
   void init(const char* arch);
   void replaceRegSets(char* buf, int bufLen);
   void destroy();
}

#endif /* _ARCHITECTURE_H_ */
