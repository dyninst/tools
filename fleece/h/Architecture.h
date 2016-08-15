#ifndef _ARCHITECTURE_H_
#define _ARCHITECTURE_H_

#include <string>
#include <iostream>
#include "Alias.h"
#include "RegisterSet.h"

namespace Architecture {
   void init(char* arch);
   void replaceRegSets(char* buf, int bufLen);
   void destroy();
}

#endif /* _ARCHITECTURE_H_ */
