
#include "Alias.h"

std::map<const char*, const char*, StringUtils::str_cmp>* aliasMap = new std::map<const char*, const char*, StringUtils::str_cmp>;

bool Alias::isAlias(const char* s1, const char* s2) {
    if (std::strcmp(s1, s2) > 0) {
        s1 = s2;
    }
    return aliasMap->count(s1) != 0;
}

int Alias::addAlias(const char* s1, const char* s2) {
    if (std::strcmp(s1, s2) > 0) {
        const char* tmp = s1;
        s1 = s2;
        s2 = tmp;
    }
   
    bool inserted = aliasMap->insert(std::make_pair(s1, s2)).second;
    return inserted ? 0 : -1;
}

void Alias::destroy() {
    delete aliasMap;
}
