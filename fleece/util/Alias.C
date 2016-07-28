
#include "Alias.h"
#include <iostream>

Hashcounter* aliasHC = new Hashcounter(6871);

bool Alias::isAlias(char* s1, char* s2) {
   return aliasHC->get(s1, s2) != 0;
}

int Alias::addAlias(const char* s1, const char* s2) {
   static int aliasCount = 0;
   aliasCount++;
   aliasHC->increment(s1, s2);
   return aliasCount;
}

void Alias::destroy() {
   delete aliasHC;
}
