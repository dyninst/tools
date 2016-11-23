
#include "Architecture.h"

int Architecture::maxInsnLen;
std::vector<RegisterSet*> regSets;
std::string Architecture::name;

void addNumberedRegSet(const char* setName, const char* baseName, 
        int lowerBound, int upperBound) {

    // Make a buffer with enough room for any reasonable register numbers (up to
    // 30 digits).
    int bufLen = strlen(baseName) + 30;
    char* buf = (char*)malloc(bufLen);
    assert(buf != NULL);

    RegisterSet* regs = new RegisterSet(setName);

    for (int i = upperBound; i >= lowerBound; i--) {
       snprintf(buf, bufLen, "%s%d", baseName, i);
       regs->addRegName(buf);
    }

    regSets.push_back(regs);
    free(buf);

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
}

void init_x86_64() {

    Architecture::name = "x86_64";
    Architecture::maxInsnLen = 15;

    RegisterSet* gp_64bit = new RegisterSet("%gp_64bit");

    gp_64bit->addRegName("%rax");
    gp_64bit->addRegName("%rcx");
    gp_64bit->addRegName("%rdx");
    gp_64bit->addRegName("%rbx");
    gp_64bit->addRegName("%rsp");
    gp_64bit->addRegName("%rbp");
    gp_64bit->addRegName("%rsi");
    gp_64bit->addRegName("%rdi");

    gp_64bit->addRegName("%r8");
    gp_64bit->addRegName("%r9");
    gp_64bit->addRegName("%r10");
    gp_64bit->addRegName("%r11");
    gp_64bit->addRegName("%r12");
    gp_64bit->addRegName("%r13");
    gp_64bit->addRegName("%r14");
    gp_64bit->addRegName("%r15");

    regSets.push_back(gp_64bit);

    RegisterSet* gp_32bit = new RegisterSet("%gp_32bit");

    gp_32bit->addRegName("%eax");
    gp_32bit->addRegName("%ecx");
    gp_32bit->addRegName("%edx");
    gp_32bit->addRegName("%ebx");
    gp_32bit->addRegName("%esp");
    gp_32bit->addRegName("%ebp");
    gp_32bit->addRegName("%esi");
    gp_32bit->addRegName("%edi");

    gp_32bit->addRegName("%r8d");
    gp_32bit->addRegName("%r9d");
    gp_32bit->addRegName("%r10d");
    gp_32bit->addRegName("%r11d");
    gp_32bit->addRegName("%r12d");
    gp_32bit->addRegName("%r13d");
    gp_32bit->addRegName("%r14d");
    gp_32bit->addRegName("%r15d");

    regSets.push_back(gp_32bit);

    RegisterSet* gp_16bit = new RegisterSet("%gp_16bit");

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

    regSets.push_back(gp_16bit);

    RegisterSet* gp_8bit = new RegisterSet("%gp_8bit");

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

    regSets.push_back(gp_8bit);

    RegisterSet* seg_regs = new RegisterSet("%seg_reg");

    seg_regs->addRegName("%cs");
    seg_regs->addRegName("%ds");
    seg_regs->addRegName("%es");
    seg_regs->addRegName("%fs");
    seg_regs->addRegName("%gs");
    seg_regs->addRegName("%ss");

    regSets.push_back(seg_regs);

    RegisterSet* mmx_regs = new RegisterSet("%mmx_reg");

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

    regSets.push_back(mmx_regs);

    addNumberedRegSet("%xmm_reg", "%xmm", 0, 31);   
    addNumberedRegSet("%ymm_reg", "%ymm", 0, 31);   
    addNumberedRegSet("%zmm_reg", "%zmm", 0, 31);   
    addNumberedRegSet("k_reg", "k", 0, 7);
    addNumberedRegSet("%k_reg", "%k", 0, 7);

}

void init_aarch64() {

    Architecture::name = "aarch64";
    Architecture::maxInsnLen = 4;

    addNumberedRegSet("wreg", "w", 0, 31);
    addNumberedRegSet("xreg", "x", 0, 31);
    addNumberedRegSet("sreg", "s", 0, 31);
    addNumberedRegSet("breg", "b", 0, 31);
    addNumberedRegSet("dreg", "d", 0, 31);
    addNumberedRegSet("qreg", "q", 0, 31);
    addNumberedRegSet("hreg", "h", 0, 31);
    addNumberedRegSet("vreg", "v", 0, 31);

    Alias::addAlias("zr", "xzr");
    Alias::addAlias("zr,", "xzr,");

    /* General system registers */
    Alias::addAlias("s3_0_c1_c0_1", "actlr_el1");
    Alias::addAlias("s3_4_c1_c0_1", "actlr_el2");
    Alias::addAlias("s3_6_c1_c0_1", "actlr_el3");
    Alias::addAlias("s3_0_c5_c1_0", "afsr0_el1");
    Alias::addAlias("s3_4_c5_c1_0", "afsr0_el2");
    Alias::addAlias("s3_6_c5_c1_0", "afsr0_el3");
    Alias::addAlias("s3_0_c5_c1_1", "afsr1_el1");
    Alias::addAlias("s3_4_c5_c1_1", "afsr1_el2");
    Alias::addAlias("s3_6_c5_c1_1", "afsr1_el3");
    Alias::addAlias("s3_1_c0_c0_7", "aidr_el1");
    Alias::addAlias("s3_0_c10_c3_0", "amair_el1");
    Alias::addAlias("s3_4_c10_c3_0", "amair_el2");
    Alias::addAlias("s3_6_c10_c3_0", "amair_el3");
    Alias::addAlias("s3_1_c0_c0_0", "ccsidr_el1");
    Alias::addAlias("s3_1_c0_c0_1", "clidr_el1");
    Alias::addAlias("s3_0_c11_c0_1", "contextidr_el1");
    Alias::addAlias("s3_0_c1_c0_2", "cpacr_el1");
    Alias::addAlias("s3_4_c1_c1_2", "cptr_el2");
    Alias::addAlias("s3_6_c1_c1_2", "cptr_el3");
    Alias::addAlias("s3_2_c0_c0_0", "csselr_el1");
    Alias::addAlias("s3_3_c0_c0_1", "ctr_el0");
    Alias::addAlias("s3_4_c3_c0_0", "dacr32_el2");
    Alias::addAlias("s3_3_c0_c0_7", "dczid_el0");
    Alias::addAlias("s3_0_c5_c2_0", "esr_el1");
    Alias::addAlias("s3_4_c5_c2_0", "esr_el2");
    Alias::addAlias("s3_6_c5_c2_0", "esr_el3");
    Alias::addAlias("s3_0_c6_c0_0", "far_el1");
    Alias::addAlias("s3_4_c6_c0_0", "far_el2");
    Alias::addAlias("s3_4_c5_c3_0", "fpexc32_el2");
    Alias::addAlias("s3_4_c1_c1_7", "hacr_el2");
    Alias::addAlias("s3_4_c1_c1_0", "hcr_el2");
    Alias::addAlias("s3_4_c6_c0_4", "hpfar_el2");
    Alias::addAlias("s3_4_c1_c1_3", "hstr_el2");
    Alias::addAlias("s3_0_c0_c5_4", "id_aa64afr0_el1");
    Alias::addAlias("s3_0_c0_c5_5", "id_aa64afr1_el1");
    Alias::addAlias("s3_0_c0_c5_0", "id_aa64dfr0_el1");
    Alias::addAlias("s3_0_c0_c5_1", "id_aa64dfr1_el1");
    Alias::addAlias("s3_0_c0_c6_0", "id_aa64isar0_el1");
    Alias::addAlias("s3_0_c0_c6_1", "id_aa64isar1_el1");
    Alias::addAlias("s3_0_c0_c7_0", "id_aa64mmfr0_el1");
    Alias::addAlias("s3_0_c0_c7_1", "id_aa64mmfr1_el1");
    Alias::addAlias("s3_0_c0_c4_0", "id_aa64pfr0_el1");
    Alias::addAlias("s3_0_c0_c4_1", "id_aa64pfr1_el1");
    Alias::addAlias("s3_0_c0_c1_3", "id_afr0_el1");
    Alias::addAlias("s3_0_c0_c1_2", "id_dfr0_el1");
    Alias::addAlias("s3_0_c0_c2_0", "id_isar0_el1");
    Alias::addAlias("s3_0_c0_c2_1", "id_isar1_el1");
    Alias::addAlias("s3_0_c0_c2_2", "id_isar2_el1");
    Alias::addAlias("s3_0_c0_c2_3", "id_isar3_el1");
    Alias::addAlias("s3_0_c0_c2_4", "id_isar4_el1");
    Alias::addAlias("s3_0_c0_c2_5", "id_isar5_el1");
    Alias::addAlias("s3_0_c0_c1_4", "id_mmfr0_el1");
    Alias::addAlias("s3_0_c0_c1_5", "id_mmfr1_el1");
    Alias::addAlias("s3_0_c0_c1_6", "id_mmfr2_el1");
    Alias::addAlias("s3_0_c0_c1_7", "id_mmfr3_el1");
    Alias::addAlias("s3_0_c0_c2_6", "id_mmfr4_el1");
    Alias::addAlias("s3_0_c0_c1_0", "id_pfr0_el1");
    Alias::addAlias("s3_4_c5_c0_1", "ifsr32_el2");
    Alias::addAlias("s3_0_c12_c1_0", "isr_el1");
    Alias::addAlias("s3_0_c10_c2_0", "mair_el1");
    Alias::addAlias("s3_4_c10_c2_0", "mair_el2");
    Alias::addAlias("s3_6_c10_c2_0", "mair_el3");
    Alias::addAlias("s3_0_c0_c0_0", "midr_el1");
    Alias::addAlias("s3_0_c0_c0_5", "mpidr_el1");
    Alias::addAlias("s3_0_c0_c3_0", "mvfr0_el1");
    Alias::addAlias("s3_0_c0_c3_0", "mvfr1_el1");
    Alias::addAlias("s3_0_c0_c3_0", "mvfr2_el1");
    Alias::addAlias("s3_0_c7_c4_0", "par_el1");
    Alias::addAlias("s3_0_c0_c0_6", "revidr_el1");
    Alias::addAlias("s3_0_c12_c0_2", "rmr_el1");
    Alias::addAlias("s3_4_c12_c0_2", "rmr_el2");
    Alias::addAlias("s3_6_c12_c0_2", "rmr_el3");
    Alias::addAlias("s3_0_c12_c0_1", "rvbar_el1");
    Alias::addAlias("s3_4_c12_c0_1", "rvbar_el2");
    Alias::addAlias("s3_6_c12_c0_1", "rvbar_el3");
   
    /* Not a real alias, acts as a place-holder. */
    Alias::addAlias("s3_xxx_c1x11_cxxxx_xxx", "IMPLEMENTATION DEFINED");

    Alias::addAlias("s3_6_c1_c1_0", "scr_el3");
    Alias::addAlias("s3_0_c1_c0_0", "sctlr_el1");
    Alias::addAlias("s3_4_c1_c0_0", "sctlr_el2");
    Alias::addAlias("s3_6_c1_c0_0", "sctlr_el3");
    Alias::addAlias("s3_6_c1_c0_0", "sctlr_el3");
    Alias::addAlias("s3_0_c2_c0_2", "tcr_el1");
    Alias::addAlias("s3_4_c2_c0_2", "tcr_el2");
    Alias::addAlias("s3_6_c2_c0_2", "tcr_el3");
    Alias::addAlias("s3_3_c13_c0_2", "tpidr_el0");
    Alias::addAlias("s3_0_c13_c0_2", "tpidr_el1");
    Alias::addAlias("s3_4_c13_c0_2", "tpidr_el2");
    Alias::addAlias("s3_6_c13_c0_2", "tpidr_el3");
    Alias::addAlias("s3_3_c13_c0_3", "tpidrro_el0");
    Alias::addAlias("s3_0_c2_c0_0", "ttbr0_el1");
    Alias::addAlias("s3_4_c2_c0_0", "ttbr0_el2");
    Alias::addAlias("s3_6_c2_c0_0", "ttbr0_el3");
    Alias::addAlias("s3_0_c2_c0_1", "ttbr1_el1");
    Alias::addAlias("s3_0_c12_c0_0", "vbar_el1");
    Alias::addAlias("s3_4_c12_c0_0", "vbar_el2");
    Alias::addAlias("s3_6_c12_c0_0", "vbar_el3");
    Alias::addAlias("s3_4_c0_c0_5", "vmpidr_el2");
    Alias::addAlias("s3_4_c0_c0_0", "vpidr_el2");
    Alias::addAlias("s3_4_c2_c1_2", "vtcr_el2");
    Alias::addAlias("s3_4_c2_c1_0", "vttbr_el2");
    
    /* Debug system registers */
    Alias::addAlias("s2_0_c7_c14_6", "dbgauthstatus_el1");
    Alias::addAlias("s2_0_c0_c0_5", "dbgcr0_el1");
    Alias::addAlias("s2_0_c0_c1_5", "dbgcr1_el1");
    Alias::addAlias("s2_0_c0_c2_5", "dbgcr2_el1");
    Alias::addAlias("s2_0_c0_c3_5", "dbgcr3_el1");
    Alias::addAlias("s2_0_c0_c4_5", "dbgcr4_el1");
    Alias::addAlias("s2_0_c0_c5_5", "dbgcr5_el1");
    Alias::addAlias("s2_0_c0_c6_5", "dbgcr6_el1");
    Alias::addAlias("s2_0_c0_c7_5", "dbgcr7_el1");
    Alias::addAlias("s2_0_c0_c8_5", "dbgcr8_el1");
    Alias::addAlias("s2_0_c0_c9_5", "dbgcr9_el1");
    Alias::addAlias("s2_0_c0_c10_5", "dbgcr10_el1");
    Alias::addAlias("s2_0_c0_c11_5", "dbgcr11_el1");
    Alias::addAlias("s2_0_c0_c12_5", "dbgcr12_el1");
    Alias::addAlias("s2_0_c0_c13_5", "dbgcr13_el1");
    Alias::addAlias("s2_0_c0_c14_5", "dbgcr14_el1");
    Alias::addAlias("s2_0_c0_c15_5", "dbgcr15_el1");
    Alias::addAlias("s2_0_c0_c0_4", "dbgvr0_el1");
    Alias::addAlias("s2_0_c0_c1_4", "dbgvr1_el1");
    Alias::addAlias("s2_0_c0_c2_4", "dbgvr2_el1");
    Alias::addAlias("s2_0_c0_c3_4", "dbgvr3_el1");
    Alias::addAlias("s2_0_c0_c4_4", "dbgvr4_el1");
    Alias::addAlias("s2_0_c0_c5_4", "dbgvr5_el1");
    Alias::addAlias("s2_0_c0_c6_4", "dbgvr6_el1");
    Alias::addAlias("s2_0_c0_c7_4", "dbgvr7_el1");
    Alias::addAlias("s2_0_c0_c8_4", "dbgvr8_el1");
    Alias::addAlias("s2_0_c0_c9_4", "dbgvr9_el1");
    Alias::addAlias("s2_0_c0_c10_4", "dbgvr10_el1");
    Alias::addAlias("s2_0_c0_c11_4", "dbgvr11_el1");
    Alias::addAlias("s2_0_c0_c12_4", "dbgvr12_el1");
    Alias::addAlias("s2_0_c0_c13_4", "dbgvr13_el1");
    Alias::addAlias("s2_0_c0_c14_4", "dbgvr14_el1");
    Alias::addAlias("s2_0_c0_c15_4", "dbgvr15_el1");
    Alias::addAlias("s2_0_c7_c9_6", "dbgclaimclr_el1");
    Alias::addAlias("s2_0_c7_c8_6", "dbgclaimset_el1");
    Alias::addAlias("s2_3_c0_c4_0", "dbgdtr_el0");
    Alias::addAlias("s2_3_c0_c5_0", "dbgdtrrx_el0");
    Alias::addAlias("s2_3_c0_c5_0", "dbgdtrtx_el0");
    Alias::addAlias("s2_0_c1_c4_4", "dbgprcr_el1");
    Alias::addAlias("s2_4_c0_c7_0", "dbgvcr32_el2");
    Alias::addAlias("s2_0_c0_c0_7", "dbgwcr0_el1");
    Alias::addAlias("s2_0_c0_c1_7", "dbgwcr1_el1");
    Alias::addAlias("s2_0_c0_c2_7", "dbgwcr2_el1");
    Alias::addAlias("s2_0_c0_c3_7", "dbgwcr3_el1");
    Alias::addAlias("s2_0_c0_c4_7", "dbgwcr4_el1");
    Alias::addAlias("s2_0_c0_c5_7", "dbgwcr5_el1");
    Alias::addAlias("s2_0_c0_c6_7", "dbgwcr6_el1");
    Alias::addAlias("s2_0_c0_c7_7", "dbgwcr7_el1");
    Alias::addAlias("s2_0_c0_c8_7", "dbgwcr8_el1");
    Alias::addAlias("s2_0_c0_c9_7", "dbgwcr9_el1");
    Alias::addAlias("s2_0_c0_c10_7", "dbgwcr10_el1");
    Alias::addAlias("s2_0_c0_c11_7", "dbgwcr11_el1");
    Alias::addAlias("s2_0_c0_c12_7", "dbgwcr12_el1");
    Alias::addAlias("s2_0_c0_c13_7", "dbgwcr13_el1");
    Alias::addAlias("s2_0_c0_c14_7", "dbgwcr14_el1");
    Alias::addAlias("s2_0_c0_c15_7", "dbgwcr15_el1");
    Alias::addAlias("s2_0_c0_c0_6", "dbgwvr0_el1");
    Alias::addAlias("s2_0_c0_c1_6", "dbgwvr1_el1");
    Alias::addAlias("s2_0_c0_c2_6", "dbgwvr2_el1");
    Alias::addAlias("s2_0_c0_c3_6", "dbgwvr3_el1");
    Alias::addAlias("s2_0_c0_c4_6", "dbgwvr4_el1");
    Alias::addAlias("s2_0_c0_c5_6", "dbgwvr5_el1");
    Alias::addAlias("s2_0_c0_c6_6", "dbgwvr6_el1");
    Alias::addAlias("s2_0_c0_c7_6", "dbgwvr7_el1");
    Alias::addAlias("s2_0_c0_c8_6", "dbgwvr8_el1");
    Alias::addAlias("s2_0_c0_c9_6", "dbgwvr9_el1");
    Alias::addAlias("s2_0_c0_c10_6", "dbgwvr10_el1");
    Alias::addAlias("s2_0_c0_c11_6", "dbgwvr11_el1");
    Alias::addAlias("s2_0_c0_c12_6", "dbgwvr12_el1");
    Alias::addAlias("s2_0_c0_c13_6", "dbgwvr13_el1");
    Alias::addAlias("s2_0_c0_c14_6", "dbgwvr14_el1");
    Alias::addAlias("s2_0_c0_c15_6", "dbgwvr15_el1");
    Alias::addAlias("s3_3_c4_c5_1", "dlr_el0");
    Alias::addAlias("s3_3_c4_c5_0", "dspsr_el0");
    Alias::addAlias("s2_0_c0_c2_0", "mdccint_el1");
    Alias::addAlias("s2_3_c0_c1_0", "mdccsr_el0");
    Alias::addAlias("s3_4_c1_c1_1", "mdcr_el2");
    Alias::addAlias("s3_6_c1_c1_1", "mdcr_el3");
    Alias::addAlias("s2_0_c1_c0_0", "mdrar_el1");
    Alias::addAlias("s2_0_c0_c2_2", "mdscr_el1");
    Alias::addAlias("s2_0_c1_c3_4", "osdlr_el1");
    Alias::addAlias("s2_0_c0_c0_2", "osdtrrx_el1");
    Alias::addAlias("s2_0_c0_c3_2", "osdtrtx_el1");
    Alias::addAlias("s2_0_c0_c6_2", "oseccr_el1");
    Alias::addAlias("s2_0_c1_c0_4", "oslar_el1");
    Alias::addAlias("s2_0_c1_c1_4", "oslsr_el1");
    Alias::addAlias("s3_6_c1_c1_1", "sder32_el3");
    
    /* Performance monitoring system registers */
    Alias::addAlias("s3_3_c14_c15_7", "pmccfiltr_el0");
    Alias::addAlias("s3_3_c9_c13_0", "pmccntr_el0");
    Alias::addAlias("s3_3_c9_c12_6", "pmceid0_el0");
    Alias::addAlias("s3_3_c9_c12_7", "pmceid1_el0");
    Alias::addAlias("s3_3_c9_c12_2", "pmcntenclr_el0");
    Alias::addAlias("s3_3_c9_c12_1", "pmcntenset_el0");
    Alias::addAlias("s3_3_c9_c12_0", "pmcr_el0");
    Alias::addAlias("s3_3_c14_c8_0", "pmevcntr0_el0");
    Alias::addAlias("s3_3_c14_c8_1", "pmevcntr1_el0");
    Alias::addAlias("s3_3_c14_c8_2", "pmevcntr2_el0");
    Alias::addAlias("s3_3_c14_c8_3", "pmevcntr3_el0");
    Alias::addAlias("s3_3_c14_c8_4", "pmevcntr4_el0");
    Alias::addAlias("s3_3_c14_c8_5", "pmevcntr5_el0");
    Alias::addAlias("s3_3_c14_c8_6", "pmevcntr6_el0");
    Alias::addAlias("s3_3_c14_c8_7", "pmevcntr7_el0");
    Alias::addAlias("s3_3_c14_c9_0", "pmevcntr8_el0");
    Alias::addAlias("s3_3_c14_c9_1", "pmevcntr9_el0");
    Alias::addAlias("s3_3_c14_c9_2", "pmevcntr10_el0");
    Alias::addAlias("s3_3_c14_c9_3", "pmevcntr11_el0");
    Alias::addAlias("s3_3_c14_c9_4", "pmevcntr12_el0");
    Alias::addAlias("s3_3_c14_c9_5", "pmevcntr13_el0");
    Alias::addAlias("s3_3_c14_c9_6", "pmevcntr14_el0");
    Alias::addAlias("s3_3_c14_c9_7", "pmevcntr15_el0");
    Alias::addAlias("s3_3_c14_c10_0", "pmevcntr16_el0");
    Alias::addAlias("s3_3_c14_c10_1", "pmevcntr17_el0");
    Alias::addAlias("s3_3_c14_c10_2", "pmevcntr18_el0");
    Alias::addAlias("s3_3_c14_c10_3", "pmevcntr19_el0");
    Alias::addAlias("s3_3_c14_c10_4", "pmevcntr20_el0");
    Alias::addAlias("s3_3_c14_c10_5", "pmevcntr21_el0");
    Alias::addAlias("s3_3_c14_c10_6", "pmevcntr22_el0");
    Alias::addAlias("s3_3_c14_c10_7", "pmevcntr23_el0");
    Alias::addAlias("s3_3_c14_c11_0", "pmevcntr24_el0");
    Alias::addAlias("s3_3_c14_c11_1", "pmevcntr25_el0");
    Alias::addAlias("s3_3_c14_c11_2", "pmevcntr26_el0");
    Alias::addAlias("s3_3_c14_c11_3", "pmevcntr27_el0");
    Alias::addAlias("s3_3_c14_c11_4", "pmevcntr28_el0");
    Alias::addAlias("s3_3_c14_c11_5", "pmevcntr29_el0");
    Alias::addAlias("s3_3_c14_c11_6", "pmevcntr30_el0");
    Alias::addAlias("s3_3_c14_c12_0", "pmevtyper0_el0");
    Alias::addAlias("s3_3_c14_c12_1", "pmevtyper1_el0");
    Alias::addAlias("s3_3_c14_c12_2", "pmevtyper2_el0");
    Alias::addAlias("s3_3_c14_c12_3", "pmevtyper3_el0");
    Alias::addAlias("s3_3_c14_c12_4", "pmevtyper4_el0");
    Alias::addAlias("s3_3_c14_c12_5", "pmevtyper5_el0");
    Alias::addAlias("s3_3_c14_c12_6", "pmevtyper6_el0");
    Alias::addAlias("s3_3_c14_c12_7", "pmevtyper7_el0");
    Alias::addAlias("s3_3_c14_c13_0", "pmevtyper8_el0");
    Alias::addAlias("s3_3_c14_c13_1", "pmevtyper9_el0");
    Alias::addAlias("s3_3_c14_c13_2", "pmevtyper10_el0");
    Alias::addAlias("s3_3_c14_c13_3", "pmevtyper11_el0");
    Alias::addAlias("s3_3_c14_c13_4", "pmevtyper12_el0");
    Alias::addAlias("s3_3_c14_c13_5", "pmevtyper13_el0");
    Alias::addAlias("s3_3_c14_c13_6", "pmevtyper14_el0");
    Alias::addAlias("s3_3_c14_c13_7", "pmevtyper15_el0");
    Alias::addAlias("s3_3_c14_c14_0", "pmevtyper16_el0");
    Alias::addAlias("s3_3_c14_c14_1", "pmevtyper17_el0");
    Alias::addAlias("s3_3_c14_c14_2", "pmevtyper18_el0");
    Alias::addAlias("s3_3_c14_c14_3", "pmevtyper19_el0");
    Alias::addAlias("s3_3_c14_c14_4", "pmevtyper20_el0");
    Alias::addAlias("s3_3_c14_c14_5", "pmevtyper21_el0");
    Alias::addAlias("s3_3_c14_c14_6", "pmevtyper22_el0");
    Alias::addAlias("s3_3_c14_c14_7", "pmevtyper23_el0");
    Alias::addAlias("s3_3_c14_c15_0", "pmevtyper24_el0");
    Alias::addAlias("s3_3_c14_c15_1", "pmevtyper25_el0");
    Alias::addAlias("s3_3_c14_c15_2", "pmevtyper26_el0");
    Alias::addAlias("s3_3_c14_c15_3", "pmevtyper27_el0");
    Alias::addAlias("s3_3_c14_c15_4", "pmevtyper28_el0");
    Alias::addAlias("s3_3_c14_c15_5", "pmevtyper29_el0");
    Alias::addAlias("s3_3_c14_c15_6", "pmevtyper30_el0");
    Alias::addAlias("s3_0_c9_c14_2", "pmintenclr_el1");
    Alias::addAlias("s3_0_c9_c14_1", "pmintenset_el1");
    Alias::addAlias("s3_3_c9_c12_3", "pmovsclr_el1");
    Alias::addAlias("s3_3_c9_c14_3", "pmovsset_el1");
    Alias::addAlias("s3_3_c9_c12_5", "pmselr_el0");
    Alias::addAlias("s3_3_c9_c12_4", "pmswinc_el0");
    Alias::addAlias("s3_3_c9_c14_0", "pmuserenr_el0");
    Alias::addAlias("s3_3_c9_c13_2", "pmxevcntr_el0");
    Alias::addAlias("s3_3_c9_c13_1", "pmxevtyper_el0");
   
    /* Generic timer system registers */
    Alias::addAlias("s3_3_c14_c0_0", "cntfrq_el0");
    Alias::addAlias("s3_4_c14_c1_0", "cnthctl_el2");
    Alias::addAlias("s3_4_c14_c2_1", "cnthp_ctl_el2");
    Alias::addAlias("s3_4_c14_c2_2", "cnthp_cval_el2");
    Alias::addAlias("s3_4_c14_c2_0", "cnthp_cval_el2");
    Alias::addAlias("s3_0_c14_c1_0", "cntkctl_el1");
    Alias::addAlias("s3_3_c14_c2_1", "cntp_ctl_el0");
    Alias::addAlias("s3_3_c14_c2_2", "cntp_cval_el0");
    Alias::addAlias("s3_3_c14_c2_0", "cntp_tval_el0");
    Alias::addAlias("s3_3_c14_c0_1", "cntpct_el0");
    Alias::addAlias("s3_7_c14_c2_1", "cntps_ctl_el1");
    Alias::addAlias("s3_7_c14_c2_2", "cntps_cval_el1");
    Alias::addAlias("s3_7_c14_c2_0", "cntps_tval_el1");
    Alias::addAlias("s3_3_c14_c3_1", "cntv_ctl_el0");
    Alias::addAlias("s3_3_c14_c3_2", "cntv_cval_el0");
    Alias::addAlias("s3_3_c14_c3_0", "cntv_tval_el0");
    Alias::addAlias("s3_3_c14_c0_2", "cntvct_el0");
    Alias::addAlias("s3_4_c14_c0_3", "cntvoff_el2");

    /* Generic interrupt controller CPU interface system registers */
    Alias::addAlias("s3_0_c12_c8_4", "icc_ap0r0_el1");
    Alias::addAlias("s3_0_c12_c8_5", "icc_ap0r1_el1");
    Alias::addAlias("s3_0_c12_c8_6", "icc_ap0r2_el1");
    Alias::addAlias("s3_0_c12_c8_7", "icc_ap0r3_el1");
    Alias::addAlias("s3_0_c12_c8_0", "icc_ap1r0_el1");
    Alias::addAlias("s3_0_c12_c8_1", "icc_ap1r1_el1");
    Alias::addAlias("s3_0_c12_c8_2", "icc_ap1r2_el1");
    Alias::addAlias("s3_0_c12_c8_3", "icc_ap1r3_el1");
    Alias::addAlias("s3_0_c12_c11_6", "icc_asgi1r_el1");
    Alias::addAlias("s3_0_c12_c8_3", "icc_bpr0_el1");
    Alias::addAlias("s3_0_c12_c12_3", "icc_bpr1_el1");
    Alias::addAlias("s3_0_c12_c12_4", "icc_ctlr_el1");
    Alias::addAlias("s3_6_c12_c12_4", "icc_ctlr_el3");
    Alias::addAlias("s3_0_c12_c11_1", "icc_dir_el1");
    Alias::addAlias("s3_0_c12_c8_1", "icc_eoir0_el1");
    Alias::addAlias("s3_0_c12_c12_1", "icc_eoir1_el1");
    Alias::addAlias("s3_0_c12_c8_2", "icc_hppir0_el1");
    Alias::addAlias("s3_0_c12_c12_2", "icc_hppir1_el1");
    Alias::addAlias("s3_0_c12_c8_0", "icc_iar0_el1");
    Alias::addAlias("s3_0_c12_c12_0", "icc_iar1_el1");
    Alias::addAlias("s3_0_c12_c8_7", "icc_igrpen0_el1");
    Alias::addAlias("s3_0_c12_c12_7", "icc_igrpen1_el1");
    Alias::addAlias("s3_6_c12_c12_7", "icc_igrpen1_el3");
    Alias::addAlias("s3_0_c4_c6_0", "icc_pmr_el1");
    Alias::addAlias("s3_0_c12_c11_4", "icc_rpr_el1");
    Alias::addAlias("s3_0_c12_c11_4", "icc_rpr_el1");
    Alias::addAlias("s3_0_c12_c11_7", "icc_sgi0r_el1");
    Alias::addAlias("s3_0_c12_c11_5", "icc_sgi1r_el1");
    Alias::addAlias("s3_0_c12_c12_5", "icc_sre_el1");
    Alias::addAlias("s3_4_c12_c12_5", "icc_sre_el2");
    Alias::addAlias("s3_6_c12_c12_5", "icc_sre_el3");

    /* Generic interrupt controller virtual interface system registers */
    Alias::addAlias("s3_4_c12_c8_0", "ich_ap0r0_el2");
    Alias::addAlias("s3_4_c12_c8_1", "ich_ap0r1_el2");
    Alias::addAlias("s3_4_c12_c8_2", "ich_ap0r2_el2");
    Alias::addAlias("s3_4_c12_c8_3", "ich_ap0r3_el2");
    Alias::addAlias("s3_4_c12_c9_0", "ich_ap1r0_el2");
    Alias::addAlias("s3_4_c12_c9_1", "ich_ap1r1_el2");
    Alias::addAlias("s3_4_c12_c9_2", "ich_ap1r2_el2");
    Alias::addAlias("s3_4_c12_c9_3", "ich_ap1r3_el2");
    Alias::addAlias("s3_4_c12_c11_3", "ich_eisr_el2");
    Alias::addAlias("s3_4_c12_c11_5", "ich_elrsr_el2");
    Alias::addAlias("s3_4_c12_c11_0", "ich_hcr_el2");
    Alias::addAlias("s3_4_c12_c12_0", "ich_lr0_el2");
    Alias::addAlias("s3_4_c12_c12_1", "ich_lr1_el2");
    Alias::addAlias("s3_4_c12_c12_2", "ich_lr2_el2");
    Alias::addAlias("s3_4_c12_c12_3", "ich_lr3_el2");
    Alias::addAlias("s3_4_c12_c12_4", "ich_lr4_el2");
    Alias::addAlias("s3_4_c12_c12_5", "ich_lr5_el2");
    Alias::addAlias("s3_4_c12_c12_6", "ich_lr6_el2");
    Alias::addAlias("s3_4_c12_c12_7", "ich_lr7_el2");
    Alias::addAlias("s3_4_c12_c13_0", "ich_lr8_el2");
    Alias::addAlias("s3_4_c12_c13_1", "ich_lr9_el2");
    Alias::addAlias("s3_4_c12_c13_2", "ich_lr10_el2");
    Alias::addAlias("s3_4_c12_c13_3", "ich_lr11_el2");
    Alias::addAlias("s3_4_c12_c13_4", "ich_lr12_el2");
    Alias::addAlias("s3_4_c12_c13_5", "ich_lr13_el2");
    Alias::addAlias("s3_4_c12_c13_6", "ich_lr14_el2");
    Alias::addAlias("s3_4_c12_c13_7", "ich_lr15_el2");
    Alias::addAlias("s3_4_c12_c11_2", "ich_misr_el2");
    Alias::addAlias("s3_4_c12_c11_7", "ich_vmcr_el2");
    Alias::addAlias("s3_4_c12_c11_1", "ich_vtr_el2");

}

void Architecture::init(const char* arch) {
    if (!strcmp(arch, "x86_64")) {
        init_x86_64();
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

void Architecture::replaceRegSets(FieldList& fl) {
    for (size_t i = 0; i < regSets.size(); i++) {
       regSets[i]->replaceRegNamesWithSymbol(fl);
    }
}

void Architecture::destroy() {
    for (size_t i = 0; i < regSets.size(); i++) {
        delete regSets[i];
    }
}
