#include "driver.h"
#include "scanner.h"

int main() {
    const char *fnames[] = {"add_addsub_imm", "adds_addsub_imm", "sub_addsub_imm", "subs_addsub_imm",
                            "add_addsub_ext", "adds_addsub_ext", "sub_addsub_ext", "subs_addsub_ext",
                            "add_addsub_shift", "adds_addsub_shift", "sub_addsub_shift", "subs_addsub_shift",
                            "adc", "adcs", "adr", "adrp", "b_uncond", "b_cond", "br", "blr", "bl", "cbz", "cbnz", "tbz", "tbnz",
                            "cmp_subs_addsub_imm", "cmp_subs_addsub_ext", "cmp_subs_addsub_shift",
                            "cmn_adds_addsub_imm", "cmn_adds_addsub_ext", "cmn_adds_addsub_shift",
                            "ccmn_reg", "ccmn_imm"};
    std::string pcode_files_dir("/u/s/s/ssunny/dev-home/dyninst/dyninst-code/instructionAPI/ISA_ps/");

    Dyninst_aarch64::Driver driver;
    for(int fidx = 0; fidx < sizeof(fnames)/sizeof(char *); fidx++)
        driver.pcode_parse(pcode_files_dir + std::string(fnames[fidx]));
	//driver.pcode_parse(pcode_files_dir + std::string("adrp"));

    for(int idx = 0; idx < sizeof(fnames)/sizeof(char *); idx++)
        std::cout<<"iproc_set(rose_aarch64_op_"<<fnames[idx]<<", new ARM64::IP_"<<fnames[idx]<<"_execute);"<<std::endl;

    return 0;
}
