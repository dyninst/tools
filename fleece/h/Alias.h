#ifndef _ALIAS_H_
#define _ALIAS_H_

#include <cstring>
#include <map>
#include "StringUtils.h"

namespace Alias {
   bool isAlias(const char* s1, const char* s2);
   int addAlias(const char* s1, const char* s2);
   void destroy();
}

#endif /* _ALIAS_H_ */
