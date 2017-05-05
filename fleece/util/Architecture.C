
#include <stdio.h>
#include "Architecture.h"

int Architecture::maxInsnLen;
std::vector<RegisterSet*> regSets;
std::string Architecture::name;
std::unordered_map<const char*, const char*, StringUtils::str_hash, StringUtils::str_eq> Architecture::names;

RegisterSet* addFormattedRegSet(const char* setName, const char* baseName, 
        int lowerBound, int upperBound) {

    // Make a buffer with enough room for any reasonable register numbers (up to
    // 30 digits).
    int bufLen = strlen(baseName) + 30;
    char buf[bufLen];

    RegisterSet* regs = new RegisterSet(setName);

    for (int i = upperBound; i >= lowerBound; i--) {
       snprintf(buf, bufLen, baseName, i);
       regs->addRegName(buf);
    }

    Architecture::addRegSet(regs);
    return regs;
}

RegisterSet* addNumberedRegSet(const char* setName, const char* baseName, 
        int lowerBound, int upperBound) {

    // Make a buffer with enough room for any reasonable register numbers (up to
    // 30 digits).
    int bufLen = strlen(baseName) + 30;
    char buf[bufLen];

    RegisterSet* regs = new RegisterSet(setName);

    for (int i = upperBound; i >= lowerBound; i--) {
       snprintf(buf, bufLen, "%s%d", baseName, i);
       regs->addRegName(buf);
    }

    Architecture::addRegSet(regs);
    return regs;

}

void init_armv6() {
    Architecture::name = "armv6";
    Architecture::maxInsnLen = 4;
    
    addNumberedRegSet("rreg", "r", 0, 15);
}

void init_ppc() {
    Architecture::name = "ppc";
    Architecture::maxInsnLen = 4;

    addNumberedRegSet("rreg", "r", 0, 31);
    addNumberedRegSet("freg", "f", 0, 31);
    addNumberedRegSet("fsrreg", "fsr", 0, 31);
    addNumberedRegSet("fprreg", "fpr", 0, 31);
    addNumberedRegSet("fcrreg", "fcr", 0, 31);
    addNumberedRegSet("crreg", "cr", 0, 31);
    addNumberedRegSet("creg", "c", 0, 31);
    addNumberedRegSet("vreg", "v", 0, 31);
    addNumberedRegSet("vsreg", "vs", 0, 63);
    addNumberedRegSet("segreg", "seg", 0, 4);
    addNumberedRegSet("fslreg", "fsl", 0, 31);
    
    addNumberedRegSet("rreg", "R", 0, 31);
    addNumberedRegSet("freg", "F", 0, 31);
    addNumberedRegSet("fsrreg", "FSR", 0, 31);
    addNumberedRegSet("fprreg", "FPR", 0, 31);
    addNumberedRegSet("fcrreg", "FCR", 0, 31);
    addNumberedRegSet("crreg", "CR", 0, 31);
    addNumberedRegSet("creg", "C", 0, 31);
    addNumberedRegSet("vreg", "V", 0, 31);
    addNumberedRegSet("vsreg", "VS", 0, 63);
    addNumberedRegSet("segreg", "SEG", 0, 4);
    addNumberedRegSet("fslreg", "FSL", 0, 31);

    /*
    RegisterSet* conditions = new RegisterSet("COND");

    conditions->addRegName("eq");
    conditions->addRegName("gt");
    conditions->addRegName("lt");
    conditions->addRegName("so");
    conditions->addRegName("eq");

    regSets.push_back(conditions);
    */
}

void init_x86_64() {

    Architecture::name = "x86_64";
    Architecture::maxInsnLen = 15;

    RegisterSet* gp_64bit = new RegisterSet("%reg8");

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

    gp_64bit->addRegName("%r8");
    gp_64bit->addRegName("%r9");
    gp_64bit->addRegName("%r10");
    gp_64bit->addRegName("%r11");
    gp_64bit->addRegName("%r12");
    gp_64bit->addRegName("%r13");
    gp_64bit->addRegName("%r14");
    gp_64bit->addRegName("%r15");

    Architecture::addRegSet(gp_64bit);

    RegisterSet* gp_32bit = new RegisterSet("%reg4");

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

    gp_32bit->addRegName("%r8d");
    gp_32bit->addRegName("%r9d");
    gp_32bit->addRegName("%r10d");
    gp_32bit->addRegName("%r11d");
    gp_32bit->addRegName("%r12d");
    gp_32bit->addRegName("%r13d");
    gp_32bit->addRegName("%r14d");
    gp_32bit->addRegName("%r15d");

    Architecture::addRegSet(gp_32bit);

    RegisterSet* gp_16bit = new RegisterSet("%reg2");

    gp_16bit->addRegName("%ax");
    gp_16bit->addRegName("%cx");
    gp_16bit->addRegName("%dx");
    gp_16bit->addRegName("%bx");
    gp_16bit->addRegName("%sp");
    gp_16bit->addRegName("%bp");
    gp_16bit->addRegName("%si");
    gp_16bit->addRegName("%di");

    gp_16bit->addRegName("%r8w");
    gp_16bit->addRegName("%r9w");
    gp_16bit->addRegName("%r10w");
    gp_16bit->addRegName("%r11w");
    gp_16bit->addRegName("%r12w");
    gp_16bit->addRegName("%r13w");
    gp_16bit->addRegName("%r14w");
    gp_16bit->addRegName("%r15w");

    Architecture::addRegSet(gp_16bit);

    RegisterSet* gp_8bit = new RegisterSet("%reg1");

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

    gp_8bit->addRegName("%r8b");
    gp_8bit->addRegName("%r9b");
    gp_8bit->addRegName("%r10b");
    gp_8bit->addRegName("%r11b");
    gp_8bit->addRegName("%r12b");
    gp_8bit->addRegName("%r13b");
    gp_8bit->addRegName("%r14b");
    gp_8bit->addRegName("%r15b");

    Architecture::addRegSet(gp_8bit);
    RegisterSet* seg_regs = new RegisterSet("%seg");

    seg_regs->addRegName("%cs");
    seg_regs->addRegName("%ds");
    seg_regs->addRegName("%es");
    seg_regs->addRegName("%fs");
    seg_regs->addRegName("%gs");
    seg_regs->addRegName("%ss");

    Architecture::addRegSet(seg_regs);
    
    RegisterSet* ctrl_regs = new RegisterSet("%ctrl");
    ctrl_regs->addRegName("%db0");
    ctrl_regs->addRegName("%db1");
    ctrl_regs->addRegName("%db2");
    ctrl_regs->addRegName("%db3");
    ctrl_regs->addRegName("%db4");
    ctrl_regs->addRegName("%db5");
    ctrl_regs->addRegName("%db6");
    ctrl_regs->addRegName("%db7");
    ctrl_regs->addRegName("%db8");
    ctrl_regs->addRegName("%db9");
    ctrl_regs->addRegName("%db10");
    ctrl_regs->addRegName("%db11");
    ctrl_regs->addRegName("%db12");
    ctrl_regs->addRegName("%db13");
    ctrl_regs->addRegName("%db14");
    ctrl_regs->addRegName("%db15");
    ctrl_regs->addRegName("%dr0");
    ctrl_regs->addRegName("%dr1");
    ctrl_regs->addRegName("%dr2");
    ctrl_regs->addRegName("%dr3");
    ctrl_regs->addRegName("%dr4");
    ctrl_regs->addRegName("%dr5");
    ctrl_regs->addRegName("%dr6");
    ctrl_regs->addRegName("%dr7");
    ctrl_regs->addRegName("%dr8");
    ctrl_regs->addRegName("%dr9");
    ctrl_regs->addRegName("%dr10");
    ctrl_regs->addRegName("%dr11");
    ctrl_regs->addRegName("%dr12");
    ctrl_regs->addRegName("%dr13");
    ctrl_regs->addRegName("%dr14");
    ctrl_regs->addRegName("%dr15");
    ctrl_regs->addRegName("%cr0");
    ctrl_regs->addRegName("%cr1");
    ctrl_regs->addRegName("%cr2");
    ctrl_regs->addRegName("%cr3");
    ctrl_regs->addRegName("%cr4");
    ctrl_regs->addRegName("%cr5");
    ctrl_regs->addRegName("%cr6");
    ctrl_regs->addRegName("%cr7");
    ctrl_regs->addRegName("%cr8");
    ctrl_regs->addRegName("%cr9");
    ctrl_regs->addRegName("%cr10");
    ctrl_regs->addRegName("%cr11");
    ctrl_regs->addRegName("%cr12");
    ctrl_regs->addRegName("%cr13");
    ctrl_regs->addRegName("%cr14");
    ctrl_regs->addRegName("%cr15");
    Architecture::addRegSet(ctrl_regs);

    RegisterSet* mmx_regs = new RegisterSet("%mmx_r");

    mmx_regs->addRegName("%mm0");
    mmx_regs->addRegName("%mm1");
    mmx_regs->addRegName("%mm2");
    mmx_regs->addRegName("%mm3");
    mmx_regs->addRegName("%mm4");
    mmx_regs->addRegName("%mm5");
    mmx_regs->addRegName("%mm6");
    mmx_regs->addRegName("%mm7");

    mmx_regs->addRegName("%mmx0");
    mmx_regs->addRegName("%mmx1");
    mmx_regs->addRegName("%mmx2");
    mmx_regs->addRegName("%mmx3");
    mmx_regs->addRegName("%mmx4");
    mmx_regs->addRegName("%mmx5");
    mmx_regs->addRegName("%mmx6");
    mmx_regs->addRegName("%mmx7");

    Architecture::addRegSet(mmx_regs);
    RegisterSet* st_regs = new RegisterSet("%st_r");

    st_regs->addRegName("%st0");
    st_regs->addRegName("%st1");
    st_regs->addRegName("%st2");
    st_regs->addRegName("%st3");
    st_regs->addRegName("%st4");
    st_regs->addRegName("%st5");
    st_regs->addRegName("%st6");
    st_regs->addRegName("%st7");
    
    Architecture::addRegSet(st_regs);

    addNumberedRegSet("%xmm_r", "%xmm", 0, 31);   
    addNumberedRegSet("%ymm_r", "%ymm", 0, 31);   
    addNumberedRegSet("%zmm_r", "%zmm", 0, 31);   
    addNumberedRegSet("%k_r", "k", 0, 7);
    addNumberedRegSet("%k_r", "%k", 0, 7);

}

void init_aarch64() {

    Architecture::name = "aarch64";
    Architecture::maxInsnLen = 4;

    RegisterSet* regs;

    regs = addNumberedRegSet("wreg", "w", 0, 31);
    regs->addRegName("wzr");
    //regs->addRegName("wsp");
    //regs->addRegName("WZR");
    //regs->addRegName("WSP");
    //addNumberedRegSet("wreg", "W", 0, 31);
    Architecture::addRegSet(regs);
    regs = addNumberedRegSet("xreg", "x", 0, 31);
    regs->addRegName("xzr");
    Architecture::addRegSet(regs);
    //regs->addRegName("SP");
    addNumberedRegSet("xreg", "X", 0, 31);
    addNumberedRegSet("sreg", "s", 0, 31);
    addNumberedRegSet("breg", "b", 0, 31);
    addNumberedRegSet("dreg", "d", 0, 31);
    addNumberedRegSet("qreg", "q", 0, 31);
    addNumberedRegSet("hreg", "h", 0, 31);
    addNumberedRegSet("hqreg", "hq", 0, 31);
    addNumberedRegSet("vreg", "v", 0, 31);
    addNumberedRegSet("creg", "c", 0, 16);
    addNumberedRegSet("sreg", "S", 0, 31);
    addNumberedRegSet("breg", "B", 0, 31);
    addNumberedRegSet("dreg", "D", 0, 31);
    addNumberedRegSet("qreg", "Q", 0, 31);
    addNumberedRegSet("hreg", "H", 0, 31);
    addNumberedRegSet("hqreg", "HQ", 0, 31);
    addNumberedRegSet("vreg", "V", 0, 31);
    addNumberedRegSet("creg", "C", 0, 16);

    addFormattedRegSet("vreg.1q", "v%d.1q", 0, 31);
    addFormattedRegSet("vreg.1d", "v%d.1d", 0, 31);
    addFormattedRegSet("vreg.2h", "v%d.2h", 0, 31);
    addFormattedRegSet("vreg.2d", "v%d.2d", 0, 31);
    addFormattedRegSet("vreg.2s", "v%d.2s", 0, 31);
    addFormattedRegSet("vreg.4h", "v%d.4h", 0, 31);
    addFormattedRegSet("vreg.4s", "v%d.4s", 0, 31);
    addFormattedRegSet("vreg.8h", "v%d.8h", 0, 31);
    addFormattedRegSet("vreg.8b", "v%d.8b", 0, 31);
    addFormattedRegSet("vreg.16b", "v%d.16b", 0, 31);
    addFormattedRegSet("vreg.d", "v%d.d", 0, 31);
    addFormattedRegSet("vreg.s", "v%d.s", 0, 31);
    addFormattedRegSet("vreg.h", "v%d.h", 0, 31);
    addFormattedRegSet("vreg.b", "v%d.b", 0, 31);

    RegisterSet* sysRegs = new RegisterSet("sysreg");
    char regName[100];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            for (int k = 0; k < 16; ++k) {
                for (int l = 0; l < 16; ++l) {
                    for (int m = 0; m < 8; ++m) {
                        snprintf(regName, 100, "s%d_%d_c%d_c%d_%d", i, j, k, l, m);
                        sysRegs->addRegName(regName);
                        //snprintf(regName, 100, "S%d_%d_C%d_C%d_%d", i, j, k, l, m);
                        //sysRegs->addRegName(regName);
                    }
                }
            }
        }
    }
    
    
    sysRegs->addRegName("scr_el3");
    sysRegs->addRegName("sctlr_el1");
    sysRegs->addRegName("sctlr_el2");
    sysRegs->addRegName("sctlr_el3");
    sysRegs->addRegName("sctlr_el3");
    sysRegs->addRegName("tcr_el1");
    sysRegs->addRegName("tcr_el2");
    sysRegs->addRegName("tcr_el3");
    sysRegs->addRegName("tpidr_el0");
    sysRegs->addRegName("tpidr_el1");
    sysRegs->addRegName("tpidr_el2");
    sysRegs->addRegName("tpidr_el3");
    sysRegs->addRegName("tpidrro_el0");
    sysRegs->addRegName("ttbr0_el1");
    sysRegs->addRegName("ttbr0_el2");
    sysRegs->addRegName("ttbr0_el3");
    sysRegs->addRegName("ttbr1_el1");
    sysRegs->addRegName("vbar_el1");
    sysRegs->addRegName("vbar_el2");
    sysRegs->addRegName("vbar_el3");
    sysRegs->addRegName("vmpidr_el2");
    sysRegs->addRegName("vpidr_el2");
    sysRegs->addRegName("vtcr_el2");
    sysRegs->addRegName("vttbr_el2");
    

    /* Debug system registers */
    
    sysRegs->addRegName("dbgauthstatus_el1");
    sysRegs->addRegName("dbgcr0_el1");
    sysRegs->addRegName("dbgcr1_el1");
    sysRegs->addRegName("dbgcr2_el1");
    sysRegs->addRegName("dbgcr3_el1");
    sysRegs->addRegName("dbgcr4_el1");
    sysRegs->addRegName("dbgcr5_el1");
    sysRegs->addRegName("dbgcr6_el1");
    sysRegs->addRegName("dbgcr7_el1");
    sysRegs->addRegName("dbgcr8_el1");
    sysRegs->addRegName("dbgcr9_el1");
    sysRegs->addRegName("dbgcr10_el1");
    sysRegs->addRegName("dbgcr11_el1");
    sysRegs->addRegName("dbgcr12_el1");
    sysRegs->addRegName("dbgcr13_el1");
    sysRegs->addRegName("dbgcr14_el1");
    sysRegs->addRegName("dbgcr15_el1");
    sysRegs->addRegName("dbgvr0_el1");
    sysRegs->addRegName("dbgvr1_el1");
    sysRegs->addRegName("dbgvr2_el1");
    sysRegs->addRegName("dbgvr3_el1");
    sysRegs->addRegName("dbgvr4_el1");
    sysRegs->addRegName("dbgvr5_el1");
    sysRegs->addRegName("dbgvr6_el1");
    sysRegs->addRegName("dbgvr7_el1");
    sysRegs->addRegName("dbgvr8_el1");
    sysRegs->addRegName("dbgvr9_el1");
    sysRegs->addRegName("dbgvr10_el1");
    sysRegs->addRegName("dbgvr11_el1");
    sysRegs->addRegName("dbgvr12_el1");
    sysRegs->addRegName("dbgvr13_el1");
    sysRegs->addRegName("dbgvr14_el1");
    sysRegs->addRegName("dbgvr15_el1");
    sysRegs->addRegName("dbgclaimclr_el1");
    sysRegs->addRegName("dbgclaimset_el1");
    sysRegs->addRegName("dbgdtr_el0");
    sysRegs->addRegName("dbgdtrrx_el0");
    sysRegs->addRegName("dbgdtrtx_el0");
    sysRegs->addRegName("dbgprcr_el1");
    sysRegs->addRegName("dbgvcr32_el2");
    sysRegs->addRegName("dbgwcr0_el1");
    sysRegs->addRegName("dbgwcr1_el1");
    sysRegs->addRegName("dbgwcr2_el1");
    sysRegs->addRegName("dbgwcr3_el1");
    sysRegs->addRegName("dbgwcr4_el1");
    sysRegs->addRegName("dbgwcr5_el1");
    sysRegs->addRegName("dbgwcr6_el1");
    sysRegs->addRegName("dbgwcr7_el1");
    sysRegs->addRegName("dbgwcr8_el1");
    sysRegs->addRegName("dbgwcr9_el1");
    sysRegs->addRegName("dbgwcr10_el1");
    sysRegs->addRegName("dbgwcr11_el1");
    sysRegs->addRegName("dbgwcr12_el1");
    sysRegs->addRegName("dbgwcr13_el1");
    sysRegs->addRegName("dbgwcr14_el1");
    sysRegs->addRegName("dbgwcr15_el1");
    sysRegs->addRegName("dbgwvr0_el1");
    sysRegs->addRegName("dbgwvr1_el1");
    sysRegs->addRegName("dbgwvr2_el1");
    sysRegs->addRegName("dbgwvr3_el1");
    sysRegs->addRegName("dbgwvr4_el1");
    sysRegs->addRegName("dbgwvr5_el1");
    sysRegs->addRegName("dbgwvr6_el1");
    sysRegs->addRegName("dbgwvr7_el1");
    sysRegs->addRegName("dbgwvr8_el1");
    sysRegs->addRegName("dbgwvr9_el1");
    sysRegs->addRegName("dbgwvr10_el1");
    sysRegs->addRegName("dbgwvr11_el1");
    sysRegs->addRegName("dbgwvr12_el1");
    sysRegs->addRegName("dbgwvr13_el1");
    sysRegs->addRegName("dbgwvr14_el1");
    sysRegs->addRegName("dbgwvr15_el1");
    sysRegs->addRegName("dlr_el0");
    sysRegs->addRegName("dspsr_el0");
    sysRegs->addRegName("mdccint_el1");
    sysRegs->addRegName("mdccsr_el0");
    sysRegs->addRegName("mdcr_el2");
    sysRegs->addRegName("mdcr_el3");
    sysRegs->addRegName("mdrar_el1");
    sysRegs->addRegName("mdscr_el1");
    sysRegs->addRegName("osdlr_el1");
    sysRegs->addRegName("osdtrrx_el1");
    sysRegs->addRegName("osdtrtx_el1");
    sysRegs->addRegName("oseccr_el1");
    sysRegs->addRegName("oslar_el1");
    sysRegs->addRegName("oslsr_el1");
    sysRegs->addRegName("sder32_el3");
    

    /* Performance monitoring system registers */
    
    sysRegs->addRegName("pmccfiltr_el0");
    sysRegs->addRegName("pmccntr_el0");
    sysRegs->addRegName("pmceid0_el0");
    sysRegs->addRegName("pmceid1_el0");
    sysRegs->addRegName("pmcntenclr_el0");
    sysRegs->addRegName("pmcntenset_el0");
    sysRegs->addRegName("pmcr_el0");
    sysRegs->addRegName("pmevcntr0_el0");
    sysRegs->addRegName("pmevcntr1_el0");
    sysRegs->addRegName("pmevcntr2_el0");
    sysRegs->addRegName("pmevcntr3_el0");
    sysRegs->addRegName("pmevcntr4_el0");
    sysRegs->addRegName("pmevcntr5_el0");
    sysRegs->addRegName("pmevcntr6_el0");
    sysRegs->addRegName("pmevcntr7_el0");
    sysRegs->addRegName("pmevcntr8_el0");
    sysRegs->addRegName("pmevcntr9_el0");
    sysRegs->addRegName("pmevcntr10_el0");
    sysRegs->addRegName("pmevcntr11_el0");
    sysRegs->addRegName("pmevcntr12_el0");
    sysRegs->addRegName("pmevcntr13_el0");
    sysRegs->addRegName("pmevcntr14_el0");
    sysRegs->addRegName("pmevcntr15_el0");
    sysRegs->addRegName("pmevcntr16_el0");
    sysRegs->addRegName("pmevcntr17_el0");
    sysRegs->addRegName("pmevcntr18_el0");
    sysRegs->addRegName("pmevcntr19_el0");
    sysRegs->addRegName("pmevcntr20_el0");
    sysRegs->addRegName("pmevcntr21_el0");
    sysRegs->addRegName("pmevcntr22_el0");
    sysRegs->addRegName("pmevcntr23_el0");
    sysRegs->addRegName("pmevcntr24_el0");
    sysRegs->addRegName("pmevcntr25_el0");
    sysRegs->addRegName("pmevcntr26_el0");
    sysRegs->addRegName("pmevcntr27_el0");
    sysRegs->addRegName("pmevcntr28_el0");
    sysRegs->addRegName("pmevcntr29_el0");
    sysRegs->addRegName("pmevcntr30_el0");
    sysRegs->addRegName("pmevtyper0_el0");
    sysRegs->addRegName("pmevtyper1_el0");
    sysRegs->addRegName("pmevtyper2_el0");
    sysRegs->addRegName("pmevtyper3_el0");
    sysRegs->addRegName("pmevtyper4_el0");
    sysRegs->addRegName("pmevtyper5_el0");
    sysRegs->addRegName("pmevtyper6_el0");
    sysRegs->addRegName("pmevtyper7_el0");
    sysRegs->addRegName("pmevtyper8_el0");
    sysRegs->addRegName("pmevtyper9_el0");
    sysRegs->addRegName("pmevtyper10_el0");
    sysRegs->addRegName("pmevtyper11_el0");
    sysRegs->addRegName("pmevtyper12_el0");
    sysRegs->addRegName("pmevtyper13_el0");
    sysRegs->addRegName("pmevtyper14_el0");
    sysRegs->addRegName("pmevtyper15_el0");
    sysRegs->addRegName("pmevtyper16_el0");
    sysRegs->addRegName("pmevtyper17_el0");
    sysRegs->addRegName("pmevtyper18_el0");
    sysRegs->addRegName("pmevtyper19_el0");
    sysRegs->addRegName("pmevtyper20_el0");
    sysRegs->addRegName("pmevtyper21_el0");
    sysRegs->addRegName("pmevtyper22_el0");
    sysRegs->addRegName("pmevtyper23_el0");
    sysRegs->addRegName("pmevtyper24_el0");
    sysRegs->addRegName("pmevtyper25_el0");
    sysRegs->addRegName("pmevtyper26_el0");
    sysRegs->addRegName("pmevtyper27_el0");
    sysRegs->addRegName("pmevtyper28_el0");
    sysRegs->addRegName("pmevtyper29_el0");
    sysRegs->addRegName("pmevtyper30_el0");
    sysRegs->addRegName("pmintenclr_el1");
    sysRegs->addRegName("pmintenset_el1");
    sysRegs->addRegName("pmovsclr_el1");
    sysRegs->addRegName("pmovsset_el1");
    sysRegs->addRegName("pmselr_el0");
    sysRegs->addRegName("pmswinc_el0");
    sysRegs->addRegName("pmuserenr_el0");
    sysRegs->addRegName("pmxevcntr_el0");
    sysRegs->addRegName("pmxevtyper_el0");


    /* Generic timer system registers */
    
    sysRegs->addRegName("cntfrq_el0");
    sysRegs->addRegName("cnthctl_el2");
    sysRegs->addRegName("cnthp_ctl_el2");
    sysRegs->addRegName("cnthp_cval_el2");
    sysRegs->addRegName("cnthp_cval_el2");
    sysRegs->addRegName("cntkctl_el1");
    sysRegs->addRegName("cntp_ctl_el0");
    sysRegs->addRegName("cntp_cval_el0");
    sysRegs->addRegName("cntp_tval_el0");
    sysRegs->addRegName("cntpct_el0");
    sysRegs->addRegName("cntps_ctl_el1");
    sysRegs->addRegName("cntps_cval_el1");
    sysRegs->addRegName("cntps_tval_el1");
    sysRegs->addRegName("cntv_ctl_el0");
    sysRegs->addRegName("cntv_cval_el0");
    sysRegs->addRegName("cntv_tval_el0");
    sysRegs->addRegName("cntvct_el0");
    sysRegs->addRegName("cntvoff_el2");
    

    /* Generic interrupt controller CPU interface system registers */
    
    sysRegs->addRegName("icc_ap0r0_el1");
    sysRegs->addRegName("icc_ap0r1_el1");
    sysRegs->addRegName("icc_ap0r2_el1");
    sysRegs->addRegName("icc_ap0r3_el1");
    sysRegs->addRegName("icc_ap1r0_el1");
    sysRegs->addRegName("icc_ap1r1_el1");
    sysRegs->addRegName("icc_ap1r2_el1");
    sysRegs->addRegName("icc_ap1r3_el1");
    sysRegs->addRegName("icc_asgi1r_el1");
    sysRegs->addRegName("icc_bpr0_el1");
    sysRegs->addRegName("icc_bpr1_el1");
    sysRegs->addRegName("icc_ctlr_el1");
    sysRegs->addRegName("icc_ctlr_el3");
    sysRegs->addRegName("icc_dir_el1");
    sysRegs->addRegName("icc_eoir0_el1");
    sysRegs->addRegName("icc_eoir1_el1");
    sysRegs->addRegName("icc_hppir0_el1");
    sysRegs->addRegName("icc_hppir1_el1");
    sysRegs->addRegName("icc_iar0_el1");
    sysRegs->addRegName("icc_iar1_el1");
    sysRegs->addRegName("icc_igrpen0_el1");
    sysRegs->addRegName("icc_igrpen1_el1");
    sysRegs->addRegName("icc_igrpen1_el3");
    sysRegs->addRegName("icc_pmr_el1");
    sysRegs->addRegName("icc_rpr_el1");
    sysRegs->addRegName("icc_rpr_el1");
    sysRegs->addRegName("icc_sgi0r_el1");
    sysRegs->addRegName("icc_sgi1r_el1");
    sysRegs->addRegName("icc_sre_el1");
    sysRegs->addRegName("icc_sre_el2");
    sysRegs->addRegName("icc_sre_el3");
    

    /* Generic interrupt controller virtual interface system registers */
    
    sysRegs->addRegName("ich_ap0r0_el2");
    sysRegs->addRegName("ich_ap0r1_el2");
    sysRegs->addRegName("ich_ap0r2_el2");
    sysRegs->addRegName("ich_ap0r3_el2");
    sysRegs->addRegName("ich_ap1r0_el2");
    sysRegs->addRegName("ich_ap1r1_el2");
    sysRegs->addRegName("ich_ap1r2_el2");
    sysRegs->addRegName("ich_ap1r3_el2");
    sysRegs->addRegName("ich_eisr_el2");
    sysRegs->addRegName("ich_elrsr_el2");
    sysRegs->addRegName("ich_hcr_el2");
    sysRegs->addRegName("ich_lr0_el2");
    sysRegs->addRegName("ich_lr1_el2");
    sysRegs->addRegName("ich_lr2_el2");
    sysRegs->addRegName("ich_lr3_el2");
    sysRegs->addRegName("ich_lr4_el2");
    sysRegs->addRegName("ich_lr5_el2");
    sysRegs->addRegName("ich_lr6_el2");
    sysRegs->addRegName("ich_lr7_el2");
    sysRegs->addRegName("ich_lr8_el2");
    sysRegs->addRegName("ich_lr9_el2");
    sysRegs->addRegName("ich_lr10_el2");
    sysRegs->addRegName("ich_lr11_el2");
    sysRegs->addRegName("ich_lr12_el2");
    sysRegs->addRegName("ich_lr13_el2");
    sysRegs->addRegName("ich_lr14_el2");
    sysRegs->addRegName("ich_lr15_el2");
    sysRegs->addRegName("ich_misr_el2");
    sysRegs->addRegName("ich_vmcr_el2");
    sysRegs->addRegName("ich_vtr_el2");

    /* Misc. System registers */
    sysRegs->addRegName("id_aa64mmfr0_el1");
    sysRegs->addRegName("trcacvr8");
    sysRegs->addRegName("id_aa64mmfr2_el1");
    sysRegs->addRegName("id_aa64mmfr1_el1");
    sysRegs->addRegName("amair_el1");
    sysRegs->addRegName("mvfr0_el1");
    sysRegs->addRegName("midr_el1");
    sysRegs->addRegName("mvfr1_el1");
    sysRegs->addRegName("trcdvcmr4");
    sysRegs->addRegName("trcdvcvr0");
    sysRegs->addRegName("trccntrldvr0");
    sysRegs->addRegName("trcdvcvr6");
    sysRegs->addRegName("trcdvcvr5");
    sysRegs->addRegName("trcacatr0");
    sysRegs->addRegName("trcacatr12");
    sysRegs->addRegName("trcacatr10");
    sysRegs->addRegName("trcacatr9");
    sysRegs->addRegName("trccidcvr0");
    sysRegs->addRegName("trcacvr4");
    sysRegs->addRegName("trcacvr2");
    sysRegs->addRegName("trcacvr1");
    sysRegs->addRegName("trcrsctlr16");
    sysRegs->addRegName("trcvmidcvr4");
    sysRegs->addRegName("trcvmidcvr2");
    sysRegs->addRegName("trcvmidcvr1");
    sysRegs->addRegName("trcacvr14");
    sysRegs->addRegName("trcacvr13");
    sysRegs->addRegName("trcacvr11");
    sysRegs->addRegName("trcdvcvr4");
    sysRegs->addRegName("trcacatr8");
    sysRegs->addRegName("trcacvr0");
    sysRegs->addRegName("trctraceidr");
    sysRegs->addRegName("trcvmidcvr0");
    sysRegs->addRegName("trcacvr12");
    sysRegs->addRegName("trcacvr10");
    sysRegs->addRegName("trcacvr9");
    sysRegs->addRegName("amair_el3");
    sysRegs->addRegName("mvfr2_el1");
    sysRegs->addRegName("amair_el2");
    sysRegs->addRegName("mair_el1");
    sysRegs->addRegName("trcdvcmr2");
    sysRegs->addRegName("trcdvcmr0");
    sysRegs->addRegName("trcimspec0");
    sysRegs->addRegName("trcdvcmr6");
    sysRegs->addRegName("trcdvcmr5");
    sysRegs->addRegName("trcdvcmr1");
    sysRegs->addRegName("trcseqevr0");
    sysRegs->addRegName("trcdvcvr1");
    sysRegs->addRegName("trcqctlr");
    sysRegs->addRegName("trcimspec4");
    sysRegs->addRegName("trcdvcmr6");
    sysRegs->addRegName("trcdvcmr5");
    sysRegs->addRegName("trcdvcmr1");
    sysRegs->addRegName("trcseqevr0");
    sysRegs->addRegName("trcdvcvr1");
    sysRegs->addRegName("trcqctlr");
    sysRegs->addRegName("trcimspec4");
    sysRegs->addRegName("trcimspec2");
    sysRegs->addRegName("trcimspec1");
    sysRegs->addRegName("trcextinselr");
    sysRegs->addRegName("trcseqevr2");
    sysRegs->addRegName("trcseqevr1");
    sysRegs->addRegName("dbgbvr0_el1");
    sysRegs->addRegName("trccntvr2");
    sysRegs->addRegName("trccntvr1");
    sysRegs->addRegName("dbgbcr8_el1");
    sysRegs->addRegName("trccntctlr2");
    sysRegs->addRegName("trccntctlr1");
    sysRegs->addRegName("dbgbcr4_el1");
    sysRegs->addRegName("trccntrldvr3");
    sysRegs->addRegName("dbgbcr2_el1");
    sysRegs->addRegName("dbgbcr1_el1");
    sysRegs->addRegName("trccntvr0");
    sysRegs->addRegName("trccntctlr0");
    sysRegs->addRegName("trccntrldvr2");
    sysRegs->addRegName("trccntrldvr1");
    sysRegs->addRegName("dbgbcr0_el1");
    sysRegs->addRegName("trcdvcmr7");
    sysRegs->addRegName("trcdvcvr7");
    sysRegs->addRegName("trcdvcvr3");
    sysRegs->addRegName("trcssccr0");
    sysRegs->addRegName("trcvdctlr");
    sysRegs->addRegName("trcvissctlr");
    sysRegs->addRegName("trcvmidcctlr0");
    sysRegs->addRegName("trcacatr6");
    sysRegs->addRegName("trcacatr5");
    sysRegs->addRegName("trcacatr3");
    sysRegs->addRegName("trcvictlr");
    sysRegs->addRegName("trccidcctlr0");
    sysRegs->addRegName("trcacatr4");
    sysRegs->addRegName("trcacatr2");
    sysRegs->addRegName("trcacatr1");
    sysRegs->addRegName("trcacatr13");
    sysRegs->addRegName("trcacatr14");
    sysRegs->addRegName("trcacatr11");
    sysRegs->addRegName("trcacatr15");
    sysRegs->addRegName("trccidcvr6");
    sysRegs->addRegName("trccidcvr5");
    sysRegs->addRegName("trccidcvr3");
    sysRegs->addRegName("trccidcvr4");
    sysRegs->addRegName("trccidcvr2");
    sysRegs->addRegName("trccidcvr1");
    sysRegs->addRegName("trcrsctlr8");
    sysRegs->addRegName("trcdvcvr2");
    sysRegs->addRegName("trceventctl0r");
    sysRegs->addRegName("trcacvr5");
    sysRegs->addRegName("trcacvr6");
    sysRegs->addRegName("trcrsctlr4");
    sysRegs->addRegName("trcauxctlr");
    sysRegs->addRegName("trcconfigr");
    sysRegs->addRegName("trcacvr3");
    sysRegs->addRegName("trcprocselr");
    sysRegs->addRegName("trcsspcicr4");
    sysRegs->addRegName("trcsspcicr2");
    sysRegs->addRegName("trcsspcicr1");
    sysRegs->addRegName("trcrsctlr28");
    sysRegs->addRegName("trcrsctlr26");
    sysRegs->addRegName("trcrsctlr25");
    sysRegs->addRegName("trcrsctlr22");
    sysRegs->addRegName("trcrsctlr21");
    sysRegs->addRegName("trcrsctlr19");
    sysRegs->addRegName("trcsspcicr0");
    sysRegs->addRegName("trcrsctlr24");
    sysRegs->addRegName("trcrsctlr20");
    sysRegs->addRegName("trcrsctlr18");
    sysRegs->addRegName("trcrsctlr17");
    sysRegs->addRegName("clidr_el1");
    sysRegs->addRegName("trcvmidcvr7");
    sysRegs->addRegName("trcrsctlr2");
    sysRegs->addRegName("trcacvr7");
    sysRegs->addRegName("trcvmidcvr6");
    sysRegs->addRegName("trcacvr15");
    sysRegs->addRegName("trcvmidcvr5");
    sysRegs->addRegName("trcvmidcvr3");
    sysRegs->addRegName("rvbar_el2");
    sysRegs->addRegName("mair_el3");
    sysRegs->addRegName("mair_el2");
    sysRegs->addRegName("id_pfr0_el1");
    sysRegs->addRegName("id_isar0_el1");
    sysRegs->addRegName("id_aa64pfr0_el1");
    sysRegs->addRegName("id_aa64dfr0_el1");
    sysRegs->addRegName("id_aa64isar0_el1");
    sysRegs->addRegName("aidr_el1");
    sysRegs->addRegName("trcdvcmr3");
    sysRegs->addRegName("trcimspec3");
    sysRegs->addRegName("dbgbvr8_el1");
    sysRegs->addRegName("dbgbvr2_el1");
    sysRegs->addRegName("dbgbvr1_el1");
    sysRegs->addRegName("trcoslar");
    sysRegs->addRegName("trcprgctlr");
    sysRegs->addRegName("trcimspec7");
    sysRegs->addRegName("trcimspec6");
    sysRegs->addRegName("trcimspec5");
    sysRegs->addRegName("dbgbvr6_el1");
    sysRegs->addRegName("trcseqrstevr");
    sysRegs->addRegName("dbgbvr12_el1");
    sysRegs->addRegName("dbgbvr10_el1");
    sysRegs->addRegName("dbgbvr9_el1");
    sysRegs->addRegName("dbgbvr5_el1");
    sysRegs->addRegName("dbgbvr3_el1");
    sysRegs->addRegName("dbgbvr4_el1");
    sysRegs->addRegName("dbgbcr10_el1");
    sysRegs->addRegName("trccntvr3");
    sysRegs->addRegName("dbgbcr9_el1");
    sysRegs->addRegName("dbgbcr12_el1");
    sysRegs->addRegName("dbgbcr11_el1");
    sysRegs->addRegName("dbgbcr6_el1");
    sysRegs->addRegName("trccntctlr3");
    sysRegs->addRegName("dbgbcr7_el1");
    sysRegs->addRegName("dbgbcr5_el1");
    sysRegs->addRegName("dbgbcr3_el1");
    sysRegs->addRegName("id_isar5_el1");
    sysRegs->addRegName("id_mmfr1_el1");
    sysRegs->addRegName("mpidr_el1");
    sysRegs->addRegName("trcsscsr4");
    sysRegs->addRegName("trcsscsr2");
    sysRegs->addRegName("trcssccr6");
    sysRegs->addRegName("trcsscsr0");
    sysRegs->addRegName("trcssccr4");
    sysRegs->addRegName("trcssccr2");
    sysRegs->addRegName("trcssccr1");
    sysRegs->addRegName("trceventctl1r");
    sysRegs->addRegName("trcsscsr1");
    sysRegs->addRegName("trcviiectlr");
    sysRegs->addRegName("trcvdarcctlr");
    sysRegs->addRegName("trcvdsacctlr");
    sysRegs->addRegName("trcssccr3");
    sysRegs->addRegName("trcvipcssctlr");
    sysRegs->addRegName("trcvmidcctlr1");
    sysRegs->addRegName("trccidcctlr1");
    sysRegs->addRegName("trcacatr7");
    sysRegs->addRegName("trctsctlr");
    sysRegs->addRegName("trcrsctlr12");
    sysRegs->addRegName("trcrsctlr10");
    sysRegs->addRegName("trcrsctlr6");
    sysRegs->addRegName("trccidcvr7");
    sysRegs->addRegName("trcrsctlr14");
    sysRegs->addRegName("trcrsctlr13");
    sysRegs->addRegName("trcrsctlr11");
    sysRegs->addRegName("trcrsctlr9");
    sysRegs->addRegName("trcsyncpr");
    sysRegs->addRegName("trcccctlr");
    sysRegs->addRegName("trcssccr5");
    sysRegs->addRegName("trcrsctlr7");
    sysRegs->addRegName("trcpdcr");
    sysRegs->addRegName("trcrsctlr5");
    sysRegs->addRegName("trcsspcicr7");
    sysRegs->addRegName("trcsspcicr5");
    sysRegs->addRegName("trcrsctlr29");
    sysRegs->addRegName("trcrsctlr30");
    sysRegs->addRegName("trcrsctlr27");
    sysRegs->addRegName("trcrsctlr31");
    sysRegs->addRegName("trcsspcicr6");
    sysRegs->addRegName("trcrsctlr23");
    sysRegs->addRegName("trcsspcicr3");
    sysRegs->addRegName("trcrsctlr3");
    sysRegs->addRegName("id_aa64dfr1_el1");
    sysRegs->addRegName("id_isar1_el1");
    sysRegs->addRegName("cnthp_tval_el2");
    sysRegs->addRegName("id_dfr0_el1");
    sysRegs->addRegName("id_isar2_el1");
    sysRegs->addRegName("id_pfr1_el1");
    sysRegs->addRegName("far_el1");
    sysRegs->addRegName("spsr_el1");
    sysRegs->addRegName("far_el2");
    sysRegs->addRegName("spsel");
    sysRegs->addRegName("currentel");
    sysRegs->addRegName("esr_el1");
    sysRegs->addRegName("sp_el0");
    sysRegs->addRegName("afsr0_el1");
    sysRegs->addRegName("sp_el1");
    sysRegs->addRegName("spsr_el2");
    sysRegs->addRegName("elr_el2");
    sysRegs->addRegName("spsr_el3");
    sysRegs->addRegName("elr_el1");
    sysRegs->addRegName("teecr32_el1");
    sysRegs->addRegName("csselr_el1");
    sysRegs->addRegName("ccsidr_el1");
    sysRegs->addRegName("id_mmfr2_el1");
    sysRegs->addRegName("id_aa64afr0_el1");
    sysRegs->addRegName("id_afr0_el1");
    sysRegs->addRegName("id_mmfr0_el1");
    sysRegs->addRegName("id_isar4_el1");
    sysRegs->addRegName("id_isar3_el1");
    sysRegs->addRegName("id_aa64isar1_el1");
    sysRegs->addRegName("id_aa64pfr1_el1");
    sysRegs->addRegName("dbgbvr14_el1");
    sysRegs->addRegName("dbgbvr13_el1");
    sysRegs->addRegName("dbgbvr11_el1");
    sysRegs->addRegName("dbgbvr7_el1");
    sysRegs->addRegName("trcseqstr");
    sysRegs->addRegName("dbgbvr15_el1");
    sysRegs->addRegName("dbgbcr14_el1");
    sysRegs->addRegName("dbgbcr13_el1");
    sysRegs->addRegName("dbgbcr15_el1");
    sysRegs->addRegName("id_aa64afr1_el1");
    sysRegs->addRegName("trcsscsr5");
    sysRegs->addRegName("trcsscsr7");
    sysRegs->addRegName("trcsscsr6");
    sysRegs->addRegName("trcsscsr3");
    sysRegs->addRegName("trcssccr7");
    sysRegs->addRegName("trcbbctlr");
    sysRegs->addRegName("trcstallctlr");
    sysRegs->addRegName("trcrsctlr15");
    sysRegs->addRegName("ctr_el0");
    sysRegs->addRegName("id_mmfr3_el1");
    sysRegs->addRegName("hpfar_el2");
    sysRegs->addRegName("far_el3");
    sysRegs->addRegName("esr_el2");
    sysRegs->addRegName("afsr0_el2");
    sysRegs->addRegName("afsr1_el2");
    sysRegs->addRegName("afsr1_el1");
    sysRegs->addRegName("hcr_el2");
    sysRegs->addRegName("fpexc32_el2");
    sysRegs->addRegName("afsr0_el3");
    sysRegs->addRegName("spsr_irq");
    sysRegs->addRegName("sp_el2");
    sysRegs->addRegName("isr_el1");
    sysRegs->addRegName("elr_el3");
    sysRegs->addRegName("ifsr32_el2");
    sysRegs->addRegName("rvbar_el1");
    sysRegs->addRegName("teehbr32_el1");
    sysRegs->addRegName("revidr_el1");
    sysRegs->addRegName("dczid_el0");
    sysRegs->addRegName("rvbar_el3");
    sysRegs->addRegName("actlr_el2");
    sysRegs->addRegName("actlr_el1");
    sysRegs->addRegName("actlr_el3");
    sysRegs->addRegName("esr_el3");
    sysRegs->addRegName("afsr1_el3");
    sysRegs->addRegName("cptr_el2");
    sysRegs->addRegName("spsr_und");
    sysRegs->addRegName("spsr_abt");
    sysRegs->addRegName("spsr_fiq");
    sysRegs->addRegName("contextidr_el1");
    sysRegs->addRegName("hstr_el2");
    sysRegs->addRegName("cptr_el3");
    sysRegs->addRegName("hacr_el2");
    
    Architecture::addRegSet(sysRegs);
}

void Architecture::init(const char* arch) {
    if (!strcmp(arch, "x86_64")) {
        init_x86_64();
    } else if (!strcmp(arch, "x86_32")) {
        init_x86_64();
        Architecture::name = "x86_32";
    } else if (!strcmp(arch, "aarch64")) {
        init_aarch64();
    } else if (!strcmp(arch, "ppc")) {
        init_ppc();
    } else if (!strcmp(arch, "armv6")) {
        init_armv6();
    } else {
        std::cerr << "UNKNOWN ARCHITECTURE: " << arch << "\n";
        exit(-1);
    }
}

void Architecture::addRegSet(RegisterSet* regSet) {
    std::vector<const char*> nameList = regSet->getNameList();
    const char* sym = regSet->getSymbol();
    for (size_t i = 0; i < nameList.size(); ++i) {
        names.insert(std::make_pair(nameList[i], sym));
    }
}

bool Architecture::isReg(const char* str) {
    for (size_t i = 0; i < regSets.size(); ++i) {
        if (regSets[i]->isReg(str)) {
            return true;
        }
    }
    return false;
}

void Architecture::replaceRegSets(FieldList& fl) {
    for (size_t i = 0; i < fl.size(); ++i) {
        auto name = names.find(fl.getField(i));
        if (name != names.end()) {
            fl.setField(i, name->second);
        }       
    }
    
    /*
    for (size_t i = 0; i < regSets.size(); i++) {
       regSets[i]->replaceRegNamesWithSymbol(fl);
    }
    */
}

void Architecture::destroy() {
    for (size_t i = 0; i < regSets.size(); i++) {
        delete regSets[i];
    }
}

bool isX86Prefix(const char* field) {
    return !strcmp(field, "repz") ||
           !strcmp(field, "repnz") ||
           !strcmp(field, "repe") ||
           !strcmp(field, "repne") ||
           !strcmp(field, "ss") ||
           !strcmp(field, "es") ||
           !strcmp(field, "fs") ||
           !strcmp(field, "gs") ||
           !strcmp(field, "ds") ||
           !strcmp(field, "lock");
}

const char* Architecture::getOpcode(FieldList& fl) {
    if (name != "x86_64") {
        return fl.getField(0);
    }
    for (size_t i = 0; i < fl.size(); ++i) {
        const char* field = fl.getField(i);
        if (!isX86Prefix(field)) {
            return field;
        }
    }
    return fl.getField(0);
}
