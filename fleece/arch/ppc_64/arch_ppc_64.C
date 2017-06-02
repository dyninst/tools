
#include <stdio.h>
#include "Architecture.h"
bool init_ppc_64() {
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("rreg", "r%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("freg", "f%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("fsrreg", "fsr%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("fprreg", "fpr%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("fcrreg", "fcr%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("crreg", "cr%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("creg", "c%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("vreg", "v%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("vsreg", "vs%d", 0, 63));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("segreg", "seg%d", 0, 4));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("fslreg", "fsl%d", 0, 31));
    return true;
}

Architecture* arch_ppc_64 = new Architecture("ppc_64", 4, &init_ppc_64, NULL);
