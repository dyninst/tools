
#include "Alias.h"

std::map<char*, int, StringUtils::str_cmp>* aliasMap = new std::map<char*, char*, StringUtils::str_cmp>();

bool Alias::isAlias(const char* s1, const char* s2) {
    if (std::strcmp(s1, s2) > 0) {
        s1 = s2;
    }
    return aliasMap->count(s1) != 0;
}

int Alias::addAlias(const char* s1, const char* s2) {
    if (std::strcmp(s1, s2) > 0) {
        char* tmp = s1;
        s1 = s2;
        s2 = tmp;
    }
   
    return aliasMap->insert(s1, s2).second == true ? 0 : -1;
}

void Alias::destroy() {
    delete aliasMap;
}
