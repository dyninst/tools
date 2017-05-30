
#include <stdio.h>
#include "Architecture.h"

bool x86_64_init() {
    RegisterSet* gp_64bit = RegisterSet::makeFormattedRegSet("%reg8", "%%r%d", 8, 15);
    gp_64bit->addRegName("%rax");
    gp_64bit->addRegName("%rcx");
    gp_64bit->addRegName("%rdx");
    gp_64bit->addRegName("%rbx");
    gp_64bit->addRegName("%rsp");
    gp_64bit->addRegName("%rbp");
    gp_64bit->addRegName("%rsi");
    gp_64bit->addRegName("%rdi");
    gp_64bit->addRegName("%rip");
    gp_64bit->addRegName("%riz");
    Architecture::addRegSet(gp_64bit);

    RegisterSet* gp_32bit = RegisterSet::makeFormattedRegSet("%reg4", "%%r%dd", 8, 15);
    gp_32bit->addRegName("%eax");
    gp_32bit->addRegName("%ecx");
    gp_32bit->addRegName("%edx");
    gp_32bit->addRegName("%ebx");
    gp_32bit->addRegName("%esp");
    gp_32bit->addRegName("%ebp");
    gp_32bit->addRegName("%esi");
    gp_32bit->addRegName("%edi");
    gp_32bit->addRegName("%eip");
    gp_32bit->addRegName("%eiz");
    Architecture::addRegSet(gp_32bit);

    RegisterSet* gp_16bit = RegisterSet::makeFormattedRegSet("%reg2", "%%r%dw", 8, 15);
    gp_16bit->addRegName("%ax");
    gp_16bit->addRegName("%cx");
    gp_16bit->addRegName("%dx");
    gp_16bit->addRegName("%bx");
    gp_16bit->addRegName("%sp");
    gp_16bit->addRegName("%bp");
    gp_16bit->addRegName("%si");
    gp_16bit->addRegName("%di");
    Architecture::addRegSet(gp_16bit);

    RegisterSet* gp_8bit = RegisterSet::makeFormattedRegSet("%reg1", "%%r%db", 8, 15);
    gp_8bit->addRegName("%ah");
    gp_8bit->addRegName("%al");
    gp_8bit->addRegName("%ch");
    gp_8bit->addRegName("%cl");
    gp_8bit->addRegName("%dh");
    gp_8bit->addRegName("%dl");
    gp_8bit->addRegName("%bh");
    gp_8bit->addRegName("%bl");
    gp_8bit->addRegName("%sil");
    gp_8bit->addRegName("%dil");
    gp_8bit->addRegName("%bpl");
    gp_8bit->addRegName("%spl");
    Architecture::addRegSet(gp_8bit);
    
    RegisterSet* seg_regs = new RegisterSet("%seg");
    seg_regs->addRegName("%cs");
    seg_regs->addRegName("%ds");
    seg_regs->addRegName("%es");
    seg_regs->addRegName("%fs");
    seg_regs->addRegName("%gs");
    seg_regs->addRegName("%ss");
    Architecture::addRegSet(seg_regs);
    
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%ctrl", "%%db%d", 0, 15));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%ctrl", "%%dr%d", 0, 15));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%ctrl", "%%cr%d", 0, 15));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%mmx_r", "%%mmx%d", 0, 7));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%mmx_r", "%%mm%d", 0, 7));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%st_r", "%%st%d", 0, 7));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%xmm_r", "%%xmm%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%ymm_r", "%%ymm%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%zmm_r", "%%zmm%d", 0, 31));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%k_r", "%%k%d", 0, 7));
    Architecture::addRegSet(RegisterSet::makeFormattedRegSet("%k_r", "k%d", 0, 7));

    return true;
}

Architecture arch_x86_64 = Architecture("x86_64", 15, &x86_64_init);
