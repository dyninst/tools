
#include <stdio.h>
#include "Architecture.h"

bool init_armv6() {
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("rreg", "r%d", 0, 15));
    return true;
}

Architecture* arch_armv6 = new Architecture("armv6", 4, &init_armv6);
