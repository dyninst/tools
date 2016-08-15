
#include "Architecture.h"

std::vector<RegisterSet*> regSets;

void addNumberedRegSet(const char* setName, const char* baseName, int lowerBound, int upperBound) {

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

}

void init_x86_64() {
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

   addNumberedRegSet("%xmm_reg", "%xmm", 0, 15);   
   addNumberedRegSet("%ymm_reg", "%ymm", 0, 15);   
   addNumberedRegSet("%zmm_reg", "%zmm", 0, 31);   

   // Rep prefixes are not truly a register set, but I want to have the same
   // effect. Seeing one rep prefix is equivalent to seeing any of the others,
   // much like a register in a register set.
   RegisterSet* rep_prefixes = new RegisterSet("rp_prefix");

   rep_prefixes->addRegName("repne");
   rep_prefixes->addRegName("repnz");
   rep_prefixes->addRegName("repe");
   rep_prefixes->addRegName("repz");
   rep_prefixes->addRegName("rep");

   regSets.push_back(rep_prefixes);

   Alias::addAlias("jz", "je");
   Alias::addAlias("ja", "jnbe");
   Alias::addAlias("jnb", "jae");
   Alias::addAlias("jnl", "jge");
   Alias::addAlias("jnle", "jg");
   Alias::addAlias("jnz", "jne");
}

void init_aarch64() {

   addNumberedRegSet("wreg", "w", 0, 31);
   addNumberedRegSet("xreg", "x", 0, 31);
   addNumberedRegSet("sreg", "s", 0, 31);
   addNumberedRegSet("dreg", "d", 0, 31);
   addNumberedRegSet("qreg", "q", 0, 31);
   addNumberedRegSet("hreg", "h", 0, 31);
   addNumberedRegSet("vreg", "v", 0, 31);

   Alias::addAlias("trcprgctlr", "s2_1_c0_c1_0");
   Alias::addAlias("trcprocselr", "s2_1_c0_c2_0");
   Alias::addAlias("trcstatr", "s2_1_c0_c3_0");
   Alias::addAlias("trcconfigr", "s2_1_c0_c4_0");
   Alias::addAlias("trcauxctlr", "s2_1_c0_c6_0");
   Alias::addAlias("trceventctl0r", "s2_1_c0_c8_0");
   Alias::addAlias("trcstallctlr", "s2_1_c0_c11_0");
   Alias::addAlias("trctsctlr", "s2_1_c0_c12_0");
   Alias::addAlias("trcsyncpr", "s2_1_c0_c13_0");
   Alias::addAlias("trcccctlr", "s2_1_c0_c14_0");
   Alias::addAlias("trcbbctlr", "s2_1_c0_c15_0");
   Alias::addAlias("s3_5_c1_c0_0", "sctlr_el12");
   Alias::addAlias("trcrsctlr2", "s2_1_c1_c2_0");
   Alias::addAlias("trcacvr0", "s2_1_c2_c0_0");
   Alias::addAlias("s3_5_c2_c0_0", "ttbr0_el12");
   Alias::addAlias("trccidcvr0", "s2_1_c3_c0_0");
   Alias::addAlias("s3_5_c4_c0_0", "spsr_el12");
   Alias::addAlias("icc_pmr_el1", "s3_0_c4_c6_0");
   Alias::addAlias("s3_5_c5_c1_0", "afsr0_el12");
   Alias::addAlias("s3_5_c5_c2_0", "esr_el12");
   Alias::addAlias("s3_0_c5_c3_0", "erridr_el1");
   Alias::addAlias("s3_0_c5_c4_0", "erxfr_el1");
   Alias::addAlias("s3_0_c5_c5_0", "erxmisc0_el1");
   Alias::addAlias("s3_5_c6_c0_0", "far_el12");
   Alias::addAlias("s3_0_c9_c9_0", "pmscr_el1");
   Alias::addAlias("s3_0_c9_c10_0", "pmblimitr_el1");
   Alias::addAlias("s3_5_c10_c2_0", "mair_el12");
   Alias::addAlias("s3_5_c10_c3_0", "amair_el12");
   Alias::addAlias("s3_5_c12_c0_0", "vbar_el12");
   Alias::addAlias("icc_iar0_el1", "s3_0_c12_c8_0");
   Alias::addAlias("ich_ap0r0_el2", "s3_4_c12_c8_0");
   Alias::addAlias("icc_ap1r0_el1", "s3_0_c12_c9_0");
   Alias::addAlias("ich_hcr_el2", "s3_4_c12_c11_0");
   Alias::addAlias("ich_lr0_el2", "s3_4_c12_c12_0");
   Alias::addAlias("icc_seien_el1", "s3_0_c12_c13_0");
   Alias::addAlias("s3_5_c14_c1_0", "cntkctl_el12");
   Alias::addAlias("s3_5_c14_c2_0", "cntp_tval_el02");
   Alias::addAlias("s3_4_c14_c3_0", "cnthv_tval_el2");
   Alias::addAlias("s3_5_c14_c3_0", "cntv_tval_el02");
   Alias::addAlias("trcprgctlr", "s2_1_c0_c1_0");
   Alias::addAlias("trcprocselr", "s2_1_c0_c2_0");
   Alias::addAlias("trcstatr", "s2_1_c0_c3_0");
   Alias::addAlias("trcconfigr", "s2_1_c0_c4_0");
   Alias::addAlias("trcauxctlr", "s2_1_c0_c6_0");
   Alias::addAlias("trceventctl0r", "s2_1_c0_c8_0");
   Alias::addAlias("trcstallctlr", "s2_1_c0_c11_0");
   Alias::addAlias("trctsctlr", "s2_1_c0_c12_0");
   Alias::addAlias("trcsyncpr", "s2_1_c0_c13_0");
   Alias::addAlias("trcccctlr", "s2_1_c0_c14_0");
   Alias::addAlias("trcbbctlr", "s2_1_c0_c15_0");
   Alias::addAlias("s3_5_c1_c0_0", "sctlr_el12");
   Alias::addAlias("trcrsctlr2", "s2_1_c1_c2_0");
   Alias::addAlias("trcacvr0", "s2_1_c2_c0_0");
   Alias::addAlias("s3_5_c2_c0_0", "ttbr0_el12");
   Alias::addAlias("trccidcvr0", "s2_1_c3_c0_0");
   Alias::addAlias("s3_5_c4_c0_0", "spsr_el12");
   Alias::addAlias("icc_pmr_el1", "s3_0_c4_c6_0");
   Alias::addAlias("s3_5_c5_c1_0", "afsr0_el12");
   Alias::addAlias("s3_5_c5_c2_0", "esr_el12");
   Alias::addAlias("s3_0_c5_c3_0", "erridr_el1");
   Alias::addAlias("s3_0_c5_c4_0", "erxfr_el1");
   Alias::addAlias("s3_0_c5_c5_0", "erxmisc0_el1");
   Alias::addAlias("s3_5_c6_c0_0", "far_el12");
   Alias::addAlias("s3_0_c9_c9_0", "pmscr_el1");
   Alias::addAlias("s3_0_c9_c10_0", "pmblimitr_el1");
   Alias::addAlias("s3_5_c10_c2_0", "mair_el12");
   Alias::addAlias("s3_5_c10_c3_0", "amair_el12");
   Alias::addAlias("s3_5_c12_c0_0", "vbar_el12");
   Alias::addAlias("icc_iar0_el1", "s3_0_c12_c8_0");
   Alias::addAlias("ich_ap0r0_el2", "s3_4_c12_c8_0");
   Alias::addAlias("icc_ap1r0_el1", "s3_0_c12_c9_0");
   Alias::addAlias("ich_hcr_el2", "s3_4_c12_c11_0");
   Alias::addAlias("ich_lr0_el2", "s3_4_c12_c12_0");
   Alias::addAlias("icc_seien_el1", "s3_0_c12_c13_0");
   Alias::addAlias("s3_5_c14_c1_0", "cntkctl_el12");
   Alias::addAlias("s3_5_c14_c2_0", "cntp_tval_el02");
   Alias::addAlias("s3_4_c14_c3_0", "cnthv_tval_el2");
   Alias::addAlias("s3_5_c14_c3_0", "cntv_tval_el02");
   Alias::addAlias("trctraceidr", "s2_1_c0_c0_1");
   Alias::addAlias("trcqctlr", "s2_1_c0_c1_1");
   Alias::addAlias("trcvmidcvr0", "s2_1_c3_c0_1");
   Alias::addAlias("s3_5_c4_c0_1", "elr_el12");
   Alias::addAlias("s3_0_c5_c3_1", "errselr_el1");
   Alias::addAlias("s3_0_c5_c4_1", "erxctlr_el1");
   Alias::addAlias("s3_0_c9_c10_1", "pmbptr_el1");
   Alias::addAlias("s3_0_c12_c1_1", "disr_el1");
   Alias::addAlias("s3_4_c12_c1_1", "vdisr_el2");
   Alias::addAlias("ich_vtr_el2", "s3_4_c12_c11_1");
   Alias::addAlias("s3_4_c13_c0_1", "contextidr_el2");
   Alias::addAlias("s3_5_c14_c2_1", "cntp_ctl_el02");
   Alias::addAlias("s3_4_c14_c3_1", "cnthv_ctl_el2");
   Alias::addAlias("s3_5_c14_c3_1", "cntv_ctl_el02");
   Alias::addAlias("trctraceidr", "s2_1_c0_c0_1");
   Alias::addAlias("trcqctlr", "s2_1_c0_c1_1");
   Alias::addAlias("trcvmidcvr0", "s2_1_c3_c0_1");
   Alias::addAlias("s3_5_c4_c0_1", "elr_el12");
   Alias::addAlias("s3_0_c5_c3_1", "errselr_el1");
   Alias::addAlias("s3_0_c5_c4_1", "erxctlr_el1");
   Alias::addAlias("s3_0_c9_c10_1", "pmbptr_el1");
   Alias::addAlias("s3_0_c12_c1_1", "disr_el1");
   Alias::addAlias("s3_4_c12_c1_1", "vdisr_el2");
   Alias::addAlias("ich_vtr_el2", "s3_4_c12_c11_1");
   Alias::addAlias("s3_4_c13_c0_1", "contextidr_el2");
   Alias::addAlias("s3_5_c14_c2_1", "cntp_ctl_el02");
   Alias::addAlias("s3_4_c14_c3_1", "cnthv_ctl_el2");
   Alias::addAlias("s3_5_c14_c3_1", "cntv_ctl_el02");
   Alias::addAlias("trcvictlr", "s2_1_c0_c0_2");
   Alias::addAlias("trcviiectlr", "s2_1_c0_c1_2");
   Alias::addAlias("trcvissctlr", "s2_1_c0_c2_2");
   Alias::addAlias("trcvipcssctlr", "s2_1_c0_c3_2");
   Alias::addAlias("s3_0_c0_c7_2", "id_aa64mmfr2_el1");
   Alias::addAlias("trcvdctlr", "s2_1_c0_c8_2");
   Alias::addAlias("trcvdsacctlr", "s2_1_c0_c9_2");
   Alias::addAlias("trcvdarcctlr", "s2_1_c0_c10_2");
   Alias::addAlias("trcssccr0", "s2_1_c1_c0_2");
   Alias::addAlias("s3_5_c1_c0_2", "cpacr_el12");
   Alias::addAlias("trcsscsr0", "s2_1_c1_c8_2");
   Alias::addAlias("trcacatr0", "s2_1_c2_c0_2");
   Alias::addAlias("s3_5_c2_c0_2", "tcr_el12");
   Alias::addAlias("trccidcctlr0", "s2_1_c3_c0_2");
   Alias::addAlias("trcvmidcctlr0", "s2_1_c3_c2_2");
   Alias::addAlias("s3_0_c5_c4_2", "erxstatus_el1");
   Alias::addAlias("s3_0_c9_c9_2", "pmsicr_el1");
   Alias::addAlias("icc_hppir0_el1", "s3_0_c12_c8_2");
   Alias::addAlias("ich_misr_el2", "s3_4_c12_c11_2");
   Alias::addAlias("s3_5_c14_c2_2", "cntp_cval_el02");
   Alias::addAlias("s3_4_c14_c3_2", "cnthv_cval_el2");
   Alias::addAlias("s3_5_c14_c3_2", "cntv_cval_el02");
   Alias::addAlias("trcvictlr", "s2_1_c0_c0_2");
   Alias::addAlias("trcviiectlr", "s2_1_c0_c1_2");
   Alias::addAlias("trcvissctlr", "s2_1_c0_c2_2");
   Alias::addAlias("trcvipcssctlr", "s2_1_c0_c3_2");
   Alias::addAlias("s3_0_c0_c7_2", "id_aa64mmfr2_el1");
   Alias::addAlias("trcvdctlr", "s2_1_c0_c8_2");
   Alias::addAlias("trcvdsacctlr", "s2_1_c0_c9_2");
   Alias::addAlias("trcvdarcctlr", "s2_1_c0_c10_2");
   Alias::addAlias("trcssccr0", "s2_1_c1_c0_2");
   Alias::addAlias("s3_5_c1_c0_2", "cpacr_el12");
   Alias::addAlias("trcsscsr0", "s2_1_c1_c8_2");
   Alias::addAlias("trcacatr0", "s2_1_c2_c0_2");
   Alias::addAlias("s3_5_c2_c0_2", "tcr_el12");
   Alias::addAlias("trccidcctlr0", "s2_1_c3_c0_2");
   Alias::addAlias("trcvmidcctlr0", "s2_1_c3_c2_2");
   Alias::addAlias("s3_0_c5_c4_2", "erxstatus_el1");
   Alias::addAlias("s3_0_c9_c9_2", "pmsicr_el1");
   Alias::addAlias("icc_hppir0_el1", "s3_0_c12_c8_2");
   Alias::addAlias("ich_misr_el2", "s3_4_c12_c11_2");
   Alias::addAlias("s3_5_c14_c2_2", "cntp_cval_el02");
   Alias::addAlias("s3_4_c14_c3_2", "cnthv_cval_el2");
   Alias::addAlias("s3_5_c14_c3_2", "cntv_cval_el02");
   Alias::addAlias("trcsspcicr0", "s2_1_c1_c0_3");
   Alias::addAlias("s3_0_c4_c2_3", "pan");
   Alias::addAlias("s3_4_c5_c2_3", "vsesr_el2");
   Alias::addAlias("s3_0_c5_c4_3", "erxaddr_el1");
   Alias::addAlias("s3_0_c9_c9_3", "pmsirr_el1");
   Alias::addAlias("s3_0_c9_c10_3", "pmbsr_el1");
   Alias::addAlias("icc_bpr0_el1", "s3_0_c12_c8_3");
   Alias::addAlias("icc_rpr_el1", "s3_0_c12_c11_3");
   Alias::addAlias("ich_eisr_el2", "s3_4_c12_c11_3");
   Alias::addAlias("trcsspcicr0", "s2_1_c1_c0_3");
   Alias::addAlias("s3_0_c4_c2_3", "pan");
   Alias::addAlias("s3_4_c5_c2_3", "vsesr_el2");
   Alias::addAlias("s3_0_c5_c4_3", "erxaddr_el1");
   Alias::addAlias("s3_0_c9_c9_3", "pmsirr_el1");
   Alias::addAlias("s3_0_c9_c10_3", "pmbsr_el1");
   Alias::addAlias("icc_bpr0_el1", "s3_0_c12_c8_3");
   Alias::addAlias("icc_rpr_el1", "s3_0_c12_c11_3");
   Alias::addAlias("ich_eisr_el2", "s3_4_c12_c11_3");
   Alias::addAlias("trcseqevr0", "s2_1_c0_c0_4");
   Alias::addAlias("trcseqrstevr", "s2_1_c0_c6_4");
   Alias::addAlias("trcseqstr", "s2_1_c0_c7_4");
   Alias::addAlias("trcextinselr", "s2_1_c0_c8_4");
   Alias::addAlias("s2_0_c1_c0_4", "oslar_el1");
   Alias::addAlias("trcoslsr", "s2_1_c1_c1_4");
   Alias::addAlias("trcpdcr", "s2_1_c1_c4_4");
   Alias::addAlias("trcpdsr", "s2_1_c1_c5_4");
   Alias::addAlias("trcdvcvr0", "s2_1_c2_c0_4");
   Alias::addAlias("s3_0_c4_c2_4", "uao");
   Alias::addAlias("trcitctrl", "s2_1_c7_c0_4");
   Alias::addAlias("s3_0_c9_c9_4", "pmsfcr_el1");
   Alias::addAlias("s3_3_c9_c12_4", "pmswinc_el0");
   Alias::addAlias("ich_vseir_el2", "s3_4_c12_c9_4");
   Alias::addAlias("icc_ctlr_el1", "s3_0_c12_c12_4");
   Alias::addAlias("trcseqevr0", "s2_1_c0_c0_4");
   Alias::addAlias("trcseqrstevr", "s2_1_c0_c6_4");
   Alias::addAlias("trcseqstr", "s2_1_c0_c7_4");
   Alias::addAlias("trcextinselr", "s2_1_c0_c8_4");
   Alias::addAlias("s2_0_c1_c0_4", "oslar_el1");
   Alias::addAlias("trcoslsr", "s2_1_c1_c1_4");
   Alias::addAlias("trcpdcr", "s2_1_c1_c4_4");
   Alias::addAlias("trcpdsr", "s2_1_c1_c5_4");
   Alias::addAlias("trcdvcvr0", "s2_1_c2_c0_4");
   Alias::addAlias("s3_0_c4_c2_4", "uao");
   Alias::addAlias("trcitctrl", "s2_1_c7_c0_4");
   Alias::addAlias("s3_0_c9_c9_4", "pmsfcr_el1");
   Alias::addAlias("s3_3_c9_c12_4", "pmswinc_el0");
   Alias::addAlias("ich_vseir_el2", "s3_4_c12_c9_4");
   Alias::addAlias("icc_ctlr_el1", "s3_0_c12_c12_4");
   Alias::addAlias("trccntrldvr0", "s2_1_c0_c0_5");
   Alias::addAlias("trccntctlr0", "s2_1_c0_c4_5");
   Alias::addAlias("trccntvr0", "s2_1_c0_c8_5");
   Alias::addAlias("s3_0_c9_c9_5", "pmsevfr_el1");
   Alias::addAlias("icc_sre_el2", "s3_4_c12_c9_5");
   Alias::addAlias("ich_elsr_el2", "s3_4_c12_c11_5");
   Alias::addAlias("trccntrldvr0", "s2_1_c0_c0_5");
   Alias::addAlias("trccntctlr0", "s2_1_c0_c4_5");
   Alias::addAlias("trccntvr0", "s2_1_c0_c8_5");
   Alias::addAlias("s3_0_c9_c9_5", "pmsevfr_el1");
   Alias::addAlias("icc_sre_el2", "s3_4_c12_c9_5");
   Alias::addAlias("ich_elsr_el2", "s3_4_c12_c11_5");
   Alias::addAlias("trcidr8", "s2_1_c0_c0_6");
   Alias::addAlias("trcdvcmr0", "s2_1_c2_c0_6");
   Alias::addAlias("trcclaimset", "s2_1_c7_c8_6");
   Alias::addAlias("trcclaimclr", "s2_1_c7_c9_6");
   Alias::addAlias("trcdevaff0", "s2_1_c7_c10_6");
   Alias::addAlias("trclsr", "s2_1_c7_c13_6");
   Alias::addAlias("trcauthstatus", "s2_1_c7_c14_6");
   Alias::addAlias("trcdevarch", "s2_1_c7_c15_6");
   Alias::addAlias("s3_0_c9_c9_6", "pmslatfr_el1");
   Alias::addAlias("icc_igrpen0_el1", "s3_0_c12_c12_6");
   Alias::addAlias("trcidr8", "s2_1_c0_c0_6");
   Alias::addAlias("trcdvcmr0", "s2_1_c2_c0_6");
   Alias::addAlias("trcclaimset", "s2_1_c7_c8_6");
   Alias::addAlias("trcclaimclr", "s2_1_c7_c9_6");
   Alias::addAlias("trcdevaff0", "s2_1_c7_c10_6");
   Alias::addAlias("trclsr", "s2_1_c7_c13_6");
   Alias::addAlias("trcauthstatus", "s2_1_c7_c14_6");
   Alias::addAlias("trcdevarch", "s2_1_c7_c15_6");
   Alias::addAlias("s3_0_c9_c9_6", "pmslatfr_el1");
   Alias::addAlias("icc_igrpen0_el1", "s3_0_c12_c12_6");
   Alias::addAlias("trcimspec0", "s2_1_c0_c0_7");
   Alias::addAlias("trcdevid", "s2_1_c7_c2_7");
   Alias::addAlias("trcdevtype", "s2_1_c7_c3_7");
   Alias::addAlias("trcpidr4", "s2_1_c7_c4_7");
   Alias::addAlias("trccidr0", "s2_1_c7_c12_7");
   Alias::addAlias("s3_0_c9_c9_7", "pmsidr_el1");
   Alias::addAlias("s3_0_c9_c10_7", "pmbidr_el1");
   Alias::addAlias("ich_vmcr_el2", "s3_4_c12_c11_7");
   Alias::addAlias("trcimspec0", "s2_1_c0_c0_7");
   Alias::addAlias("trcdevid", "s2_1_c7_c2_7");
   Alias::addAlias("trcdevtype", "s2_1_c7_c3_7");
   Alias::addAlias("trcpidr4", "s2_1_c7_c4_7");
   Alias::addAlias("trccidr0", "s2_1_c7_c12_7");
   Alias::addAlias("s3_0_c9_c9_7", "pmsidr_el1");
   Alias::addAlias("s3_0_c9_c10_7", "pmbidr_el1");
   Alias::addAlias("ich_vmcr_el2", "s3_4_c12_c11_7");
   Alias::addAlias("s3_0_c0_c0_0", "midr_el1");
   Alias::addAlias("s3_1_c0_c0_0", "ccsidr_el1");
   Alias::addAlias("trcprgctlr", "s2_1_c0_c1_0");
   Alias::addAlias("s2_3_c0_c1_0", "mdccsr_el0");
   Alias::addAlias("s3_0_c0_c1_0", "id_pfr0_el1");
   Alias::addAlias("trcprocselr", "s2_1_c0_c2_0");
   Alias::addAlias("s3_0_c0_c2_0", "id_isar0_el1");
   Alias::addAlias("s3_0_c0_c3_0", "mvfr0_el1");
   Alias::addAlias("trcconfigr", "s2_1_c0_c4_0");
   Alias::addAlias("s3_0_c0_c4_0", "id_aa64pfr0_el1");
   Alias::addAlias("dbgdtrtx_el0", "dbgdtrrx_el0");
   Alias::addAlias("s3_0_c0_c5_0", "id_aa64dfr0_el1");
   Alias::addAlias("trcauxctlr", "s2_1_c0_c6_0");
   Alias::addAlias("s3_0_c0_c6_0", "id_aa64isar0_el1");
   Alias::addAlias("s3_0_c0_c7_0", "id_aa64mmfr0_el1");
   Alias::addAlias("trceventctl0r", "s2_1_c0_c8_0");
   Alias::addAlias("trcstallctlr", "s2_1_c0_c11_0");
   Alias::addAlias("trctsctlr", "s2_1_c0_c12_0");
   Alias::addAlias("trcsyncpr", "s2_1_c0_c13_0");
   Alias::addAlias("trcccctlr", "s2_1_c0_c14_0");
   Alias::addAlias("trcbbctlr", "s2_1_c0_c15_0");
   Alias::addAlias("s2_0_c1_c0_0", "mdrar_el1");
   Alias::addAlias("s3_5_c1_c0_0", "sctlr_el12");
   Alias::addAlias("trcrsctlr2", "s2_1_c1_c2_0");
   Alias::addAlias("trcacvr0", "s2_1_c2_c0_0");
   Alias::addAlias("s3_5_c2_c0_0", "ttbr0_el12");
   Alias::addAlias("trccidcvr0", "s2_1_c3_c0_0");
   Alias::addAlias("s3_5_c4_c0_0", "spsr_el12");
   Alias::addAlias("icc_pmr_el1", "s3_0_c4_c6_0");
   Alias::addAlias("s3_5_c5_c1_0", "afsr0_el12");
   Alias::addAlias("s3_5_c5_c2_0", "esr_el12");
   Alias::addAlias("s3_0_c5_c3_0", "erridr_el1");
   Alias::addAlias("s3_0_c5_c4_0", "erxfr_el1");
   Alias::addAlias("s3_0_c5_c5_0", "erxmisc0_el1");
   Alias::addAlias("s3_5_c6_c0_0", "far_el12");
   Alias::addAlias("s3_0_c9_c9_0", "pmscr_el1");
   Alias::addAlias("s3_0_c9_c10_0", "pmblimitr_el1");
   Alias::addAlias("s3_5_c10_c2_0", "mair_el12");
   Alias::addAlias("s3_5_c10_c3_0", "amair_el12");
   Alias::addAlias("s3_5_c12_c0_0", "vbar_el12");
   Alias::addAlias("s3_0_c12_c1_0", "isr_el1");
   Alias::addAlias("ich_ap0r0_el2", "s3_4_c12_c8_0");
   Alias::addAlias("icc_ap1r0_el1", "s3_0_c12_c9_0");
   Alias::addAlias("ich_hcr_el2", "s3_4_c12_c11_0");
   Alias::addAlias("ich_lr0_el2", "s3_4_c12_c12_0");
   Alias::addAlias("icc_seien_el1", "s3_0_c12_c13_0");
   Alias::addAlias("s3_5_c14_c1_0", "cntkctl_el12");
   Alias::addAlias("s3_5_c14_c2_0", "cntp_tval_el02");
   Alias::addAlias("s3_4_c14_c3_0", "cnthv_tval_el2");
   Alias::addAlias("s3_5_c14_c3_0", "cntv_tval_el02");
   Alias::addAlias("s3_0_c0_c0_0", "midr_el1");
   Alias::addAlias("s3_1_c0_c0_0", "ccsidr_el1");
   Alias::addAlias("trcprgctlr", "s2_1_c0_c1_0");
   Alias::addAlias("s2_3_c0_c1_0", "mdccsr_el0");
   Alias::addAlias("s3_0_c0_c1_0", "id_pfr0_el1");
   Alias::addAlias("trcprocselr", "s2_1_c0_c2_0");
   Alias::addAlias("s3_0_c0_c2_0", "id_isar0_el1");
   Alias::addAlias("s3_0_c0_c3_0", "mvfr0_el1");
   Alias::addAlias("trcconfigr", "s2_1_c0_c4_0");
   Alias::addAlias("s3_0_c0_c4_0", "id_aa64pfr0_el1");
   Alias::addAlias("dbgdtrtx_el0", "dbgdtrrx_el0");
   Alias::addAlias("s3_0_c0_c5_0", "id_aa64dfr0_el1");
   Alias::addAlias("trcauxctlr", "s2_1_c0_c6_0");
   Alias::addAlias("s3_0_c0_c6_0", "id_aa64isar0_el1");
   Alias::addAlias("s3_0_c0_c7_0", "id_aa64mmfr0_el1");
   Alias::addAlias("trceventctl0r", "s2_1_c0_c8_0");
   Alias::addAlias("trcstallctlr", "s2_1_c0_c11_0");
   Alias::addAlias("trctsctlr", "s2_1_c0_c12_0");
   Alias::addAlias("trcsyncpr", "s2_1_c0_c13_0");
   Alias::addAlias("trcccctlr", "s2_1_c0_c14_0");
   Alias::addAlias("trcbbctlr", "s2_1_c0_c15_0");
   Alias::addAlias("s2_0_c1_c0_0", "mdrar_el1");
   Alias::addAlias("s3_5_c1_c0_0", "sctlr_el12");
   Alias::addAlias("trcrsctlr2", "s2_1_c1_c2_0");
   Alias::addAlias("trcacvr0", "s2_1_c2_c0_0");
   Alias::addAlias("s3_5_c2_c0_0", "ttbr0_el12");
   Alias::addAlias("trccidcvr0", "s2_1_c3_c0_0");
   Alias::addAlias("s3_5_c4_c0_0", "spsr_el12");
   Alias::addAlias("icc_pmr_el1", "s3_0_c4_c6_0");
   Alias::addAlias("s3_5_c5_c1_0", "afsr0_el12");
   Alias::addAlias("s3_5_c5_c2_0", "esr_el12");
   Alias::addAlias("s3_0_c5_c3_0", "erridr_el1");
   Alias::addAlias("s3_0_c5_c4_0", "erxfr_el1");
   Alias::addAlias("s3_0_c5_c5_0", "erxmisc0_el1");
   Alias::addAlias("s3_5_c6_c0_0", "far_el12");
   Alias::addAlias("s3_0_c9_c9_0", "pmscr_el1");
   Alias::addAlias("s3_0_c9_c10_0", "pmblimitr_el1");
   Alias::addAlias("s3_5_c10_c2_0", "mair_el12");
   Alias::addAlias("s3_5_c10_c3_0", "amair_el12");
   Alias::addAlias("s3_5_c12_c0_0", "vbar_el12");
   Alias::addAlias("s3_0_c12_c1_0", "isr_el1");
   Alias::addAlias("ich_ap0r0_el2", "s3_4_c12_c8_0");
   Alias::addAlias("icc_ap1r0_el1", "s3_0_c12_c9_0");
   Alias::addAlias("ich_hcr_el2", "s3_4_c12_c11_0");
   Alias::addAlias("ich_lr0_el2", "s3_4_c12_c12_0");
   Alias::addAlias("icc_seien_el1", "s3_0_c12_c13_0");
   Alias::addAlias("s3_5_c14_c1_0", "cntkctl_el12");
   Alias::addAlias("s3_5_c14_c2_0", "cntp_tval_el02");
   Alias::addAlias("s3_4_c14_c3_0", "cnthv_tval_el2");
   Alias::addAlias("s3_5_c14_c3_0", "cntv_tval_el02");
   Alias::addAlias("trctraceidr", "s2_1_c0_c0_1");
   Alias::addAlias("s3_1_c0_c0_1", "clidr_el1");
   Alias::addAlias("s3_3_c0_c0_1", "ctr_el0");
   Alias::addAlias("trcqctlr", "s2_1_c0_c1_1");
   Alias::addAlias("trcvmidcvr0", "s2_1_c3_c0_1");
   Alias::addAlias("s3_5_c4_c0_1", "elr_el12");
   Alias::addAlias("s3_0_c5_c3_1", "errselr_el1");
   Alias::addAlias("s3_0_c5_c4_1", "erxctlr_el1");
   Alias::addAlias("s3_0_c9_c10_1", "pmbptr_el1");
   Alias::addAlias("s3_0_c12_c0_1", "rvbar_el1");
   Alias::addAlias("s3_0_c12_c1_1", "disr_el1");
   Alias::addAlias("s3_4_c12_c1_1", "vdisr_el2");
   Alias::addAlias("icc_eoir0_el1", "s3_0_c12_c8_1");
   Alias::addAlias("icc_dir_el1", "s3_0_c12_c11_1");
   Alias::addAlias("s3_4_c13_c0_1", "contextidr_el2");
   Alias::addAlias("s3_3_c14_c0_1", "cntpct_el0");
   Alias::addAlias("s3_5_c14_c2_1", "cntp_ctl_el02");
   Alias::addAlias("s3_4_c14_c3_1", "cnthv_ctl_el2");
   Alias::addAlias("s3_5_c14_c3_1", "cntv_ctl_el02");
   Alias::addAlias("trctraceidr", "s2_1_c0_c0_1");
   Alias::addAlias("s3_1_c0_c0_1", "clidr_el1");
   Alias::addAlias("s3_3_c0_c0_1", "ctr_el0");
   Alias::addAlias("trcqctlr", "s2_1_c0_c1_1");
   Alias::addAlias("trcvmidcvr0", "s2_1_c3_c0_1");
   Alias::addAlias("s3_5_c4_c0_1", "elr_el12");
   Alias::addAlias("s3_0_c5_c3_1", "errselr_el1");
   Alias::addAlias("s3_0_c5_c4_1", "erxctlr_el1");
   Alias::addAlias("s3_0_c9_c10_1", "pmbptr_el1");
   Alias::addAlias("s3_0_c12_c0_1", "rvbar_el1");
   Alias::addAlias("s3_0_c12_c1_1", "disr_el1");
   Alias::addAlias("s3_4_c12_c1_1", "vdisr_el2");
   Alias::addAlias("icc_eoir0_el1", "s3_0_c12_c8_1");
   Alias::addAlias("icc_dir_el1", "s3_0_c12_c11_1");
   Alias::addAlias("s3_4_c13_c0_1", "contextidr_el2");
   Alias::addAlias("s3_3_c14_c0_1", "cntpct_el0");
   Alias::addAlias("s3_5_c14_c2_1", "cntp_ctl_el02");
   Alias::addAlias("s3_4_c14_c3_1", "cnthv_ctl_el2");
   Alias::addAlias("s3_5_c14_c3_1", "cntv_ctl_el02");
   Alias::addAlias("trcvictlr", "s2_1_c0_c0_2");
   Alias::addAlias("trcviiectlr", "s2_1_c0_c1_2");
   Alias::addAlias("s3_0_c0_c1_2", "id_dfr0_el1");
   Alias::addAlias("trcvissctlr", "s2_1_c0_c2_2");
   Alias::addAlias("trcvipcssctlr", "s2_1_c0_c3_2");
   Alias::addAlias("trcvdctlr", "s2_1_c0_c8_2");
   Alias::addAlias("trcvdsacctlr", "s2_1_c0_c9_2");
   Alias::addAlias("trcvdarcctlr", "s2_1_c0_c10_2");
   Alias::addAlias("trcssccr0", "s2_1_c1_c0_2");
   Alias::addAlias("s3_5_c1_c0_2", "cpacr_el12");
   Alias::addAlias("trcsscsr0", "s2_1_c1_c8_2");
   Alias::addAlias("trcacatr0", "s2_1_c2_c0_2");
   Alias::addAlias("s3_5_c2_c0_2", "tcr_el12");
   Alias::addAlias("trccidcctlr0", "s2_1_c3_c0_2");
   Alias::addAlias("trcvmidcctlr0", "s2_1_c3_c2_2");
   Alias::addAlias("s3_0_c5_c4_2", "erxstatus_el1");
   Alias::addAlias("s3_0_c9_c9_2", "pmsicr_el1");
   Alias::addAlias("ich_misr_el2", "s3_4_c12_c11_2");
   Alias::addAlias("s3_3_c14_c0_2", "cntvct_el0");
   Alias::addAlias("s3_5_c14_c2_2", "cntp_cval_el02");
   Alias::addAlias("s3_4_c14_c3_2", "cnthv_cval_el2");
   Alias::addAlias("s3_5_c14_c3_2", "cntv_cval_el02");
   Alias::addAlias("trcvictlr", "s2_1_c0_c0_2");
   Alias::addAlias("trcviiectlr", "s2_1_c0_c1_2");
   Alias::addAlias("s3_0_c0_c1_2", "id_dfr0_el1");
   Alias::addAlias("trcvissctlr", "s2_1_c0_c2_2");
   Alias::addAlias("trcvipcssctlr", "s2_1_c0_c3_2");
   Alias::addAlias("trcvdctlr", "s2_1_c0_c8_2");
   Alias::addAlias("trcvdsacctlr", "s2_1_c0_c9_2");
   Alias::addAlias("trcvdarcctlr", "s2_1_c0_c10_2");
   Alias::addAlias("trcssccr0", "s2_1_c1_c0_2");
   Alias::addAlias("s3_5_c1_c0_2", "cpacr_el12");
   Alias::addAlias("trcsscsr0", "s2_1_c1_c8_2");
   Alias::addAlias("trcacatr0", "s2_1_c2_c0_2");
   Alias::addAlias("s3_5_c2_c0_2", "tcr_el12");
   Alias::addAlias("trccidcctlr0", "s2_1_c3_c0_2");
   Alias::addAlias("trcvmidcctlr0", "s2_1_c3_c2_2");
   Alias::addAlias("s3_0_c5_c4_2", "erxstatus_el1");
   Alias::addAlias("s3_0_c9_c9_2", "pmsicr_el1");
   Alias::addAlias("ich_misr_el2", "s3_4_c12_c11_2");
   Alias::addAlias("s3_3_c14_c0_2", "cntvct_el0");
   Alias::addAlias("s3_5_c14_c2_2", "cntp_cval_el02");
   Alias::addAlias("s3_4_c14_c3_2", "cnthv_cval_el2");
   Alias::addAlias("s3_5_c14_c3_2", "cntv_cval_el02");
   Alias::addAlias("s3_0_c0_c1_3", "id_afr0_el1");
   Alias::addAlias("trcsspcicr0", "s2_1_c1_c0_3");
   Alias::addAlias("s3_0_c4_c2_3", "pan");
   Alias::addAlias("s3_4_c5_c2_3", "vsesr_el2");
   Alias::addAlias("s3_0_c5_c4_3", "erxaddr_el1");
   Alias::addAlias("s3_0_c9_c9_3", "pmsirr_el1");
   Alias::addAlias("s3_0_c9_c10_3", "pmbsr_el1");
   Alias::addAlias("icc_bpr0_el1", "s3_0_c12_c8_3");
   Alias::addAlias("s3_0_c0_c1_3", "id_afr0_el1");
   Alias::addAlias("trcsspcicr0", "s2_1_c1_c0_3");
   Alias::addAlias("s0_0_c4_c0_3", "uao");
   Alias::addAlias("s3_0_c4_c2_3", "pan");
   Alias::addAlias("s3_4_c5_c2_3", "vsesr_el2");
   Alias::addAlias("s3_0_c5_c4_3", "erxaddr_el1");
   Alias::addAlias("s3_0_c9_c9_3", "pmsirr_el1");
   Alias::addAlias("s3_0_c9_c10_3", "pmbsr_el1");
   Alias::addAlias("icc_bpr0_el1", "s3_0_c12_c8_3");
   Alias::addAlias("trcseqevr0", "s2_1_c0_c0_4");
   Alias::addAlias("s3_0_c0_c1_4", "id_mmfr0_el1");
   Alias::addAlias("s3_0_c0_c5_4", "id_aa64afr0_el1");
   Alias::addAlias("trcseqrstevr", "s2_1_c0_c6_4");
   Alias::addAlias("trcseqstr", "s2_1_c0_c7_4");
   Alias::addAlias("trcextinselr", "s2_1_c0_c8_4");
   Alias::addAlias("trcoslar", "s2_1_c1_c0_4");
   Alias::addAlias("s2_0_c1_c1_4", "oslsr_el1");
   Alias::addAlias("trcpdcr", "s2_1_c1_c4_4");
   Alias::addAlias("trcdvcvr0", "s2_1_c2_c0_4");
   Alias::addAlias("s3_0_c4_c2_4", "uao");
   Alias::addAlias("trcitctrl", "s2_1_c7_c0_4");
   Alias::addAlias("s3_0_c9_c9_4", "pmsfcr_el1");
   Alias::addAlias("ich_vseir_el2", "s3_4_c12_c9_4");
   Alias::addAlias("icc_ctlr_el1", "s3_0_c12_c12_4");
   Alias::addAlias("trcseqevr0", "s2_1_c0_c0_4");
   Alias::addAlias("s3_0_c0_c1_4", "id_mmfr0_el1");
   Alias::addAlias("s3_0_c0_c5_4", "id_aa64afr0_el1");
   Alias::addAlias("trcseqrstevr", "s2_1_c0_c6_4");
   Alias::addAlias("trcseqstr", "s2_1_c0_c7_4");
   Alias::addAlias("trcextinselr", "s2_1_c0_c8_4");
   Alias::addAlias("trcoslar", "s2_1_c1_c0_4");
   Alias::addAlias("s2_0_c1_c1_4", "oslsr_el1");
   Alias::addAlias("trcpdcr", "s2_1_c1_c4_4");
   Alias::addAlias("trcdvcvr0", "s2_1_c2_c0_4");
   Alias::addAlias("s0_0_c4_c0_4", "pan");
   Alias::addAlias("s3_0_c4_c2_4", "uao");
   Alias::addAlias("trcitctrl", "s2_1_c7_c0_4");
   Alias::addAlias("s3_0_c9_c9_4", "pmsfcr_el1");
   Alias::addAlias("ich_vseir_el2", "s3_4_c12_c9_4");
   Alias::addAlias("icc_ctlr_el1", "s3_0_c12_c12_4");
   Alias::addAlias("trccntrldvr0", "s2_1_c0_c0_5");
   Alias::addAlias("s3_0_c0_c0_5", "mpidr_el1");
   Alias::addAlias("trccntctlr0", "s2_1_c0_c4_5");
   Alias::addAlias("trccntvr0", "s2_1_c0_c8_5");
   Alias::addAlias("s3_0_c9_c9_5", "pmsevfr_el1");
   Alias::addAlias("icc_sre_el2", "s3_4_c12_c9_5");
   Alias::addAlias("icc_sgi1r_el1", "s3_0_c12_c11_5");
   Alias::addAlias("trccntrldvr0", "s2_1_c0_c0_5");
   Alias::addAlias("s3_0_c0_c0_5", "mpidr_el1");
   Alias::addAlias("trccntctlr0", "s2_1_c0_c4_5");
   Alias::addAlias("trccntvr0", "s2_1_c0_c8_5");
   Alias::addAlias("spsel", "s0_0_c4_c2_5");
   Alias::addAlias("s3_0_c9_c9_5", "pmsevfr_el1");
   Alias::addAlias("icc_sre_el2", "s3_4_c12_c9_5");
   Alias::addAlias("icc_sgi1r_el1", "s3_0_c12_c11_5");
   Alias::addAlias("s3_0_c0_c0_6", "revidr_el1");
   Alias::addAlias("trcdvcmr0", "s2_1_c2_c0_6");
   Alias::addAlias("trcclaimset", "s2_1_c7_c8_6");
   Alias::addAlias("trcclaimclr", "s2_1_c7_c9_6");
   Alias::addAlias("trclar", "s2_1_c7_c12_6");
   Alias::addAlias("s2_0_c7_c14_6", "dbgauthstatus_el1");
   Alias::addAlias("s3_0_c9_c9_6", "pmslatfr_el1");
   Alias::addAlias("s3_3_c9_c12_6", "pmceid0_el0");
   Alias::addAlias("icc_asgi1r_el1", "s3_0_c12_c11_6");
   Alias::addAlias("icc_igrpen0_el1", "s3_0_c12_c12_6");
   Alias::addAlias("s3_0_c0_c0_6", "revidr_el1");
   Alias::addAlias("trcdvcmr0", "s2_1_c2_c0_6");
   Alias::addAlias("trcclaimset", "s2_1_c7_c8_6");
   Alias::addAlias("trcclaimclr", "s2_1_c7_c9_6");
   Alias::addAlias("trclar", "s2_1_c7_c12_6");
   Alias::addAlias("s2_0_c7_c14_6", "dbgauthstatus_el1");
   Alias::addAlias("s3_0_c9_c9_6", "pmslatfr_el1");
   Alias::addAlias("s3_3_c9_c12_6", "pmceid0_el0");
   Alias::addAlias("icc_asgi1r_el1", "s3_0_c12_c11_6");
   Alias::addAlias("icc_igrpen0_el1", "s3_0_c12_c12_6");
   Alias::addAlias("trcimspec0", "s2_1_c0_c0_7");
   Alias::addAlias("s3_1_c0_c0_7", "aidr_el1");
   Alias::addAlias("s3_3_c0_c0_7", "dczid_el0");
   Alias::addAlias("s3_0_c9_c9_7", "pmsidr_el1");
   Alias::addAlias("s3_0_c9_c10_7", "pmbidr_el1");
   Alias::addAlias("ich_vmcr_el2", "s3_4_c12_c11_7");
   Alias::addAlias("trcimspec0", "s2_1_c0_c0_7");
   Alias::addAlias("s3_1_c0_c0_7", "aidr_el1");
   Alias::addAlias("s3_3_c0_c0_7", "dczid_el0");
   Alias::addAlias("s3_0_c9_c9_7", "pmsidr_el1");
   Alias::addAlias("s3_0_c9_c10_7", "pmbidr_el1");
   Alias::addAlias("ich_vmcr_el2", "s3_4_c12_c11_7");

}

void Architecture::init(char* arch) {

   if (!strcmp(arch, "x86_64")) {
      init_x86_64();
   } else if (!strcmp(arch, "aarch64")) {
      init_aarch64();
   }
}

void Architecture::replaceRegSets(char* buf, int bufLen) {

   for (size_t i = 0; i < regSets.size(); i++) {
      regSets[i]->replaceRegNamesWithSymbol(buf, bufLen);
   }
}

void Architecture::destroy() {
   for (size_t i = 0; i < regSets.size(); i++) {
      delete regSets[i];
   }
}
