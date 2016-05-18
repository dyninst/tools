#include "driver.h"
#include "scanner.h"
#include <string>
#include <vector>

int main() {
    const char *fnames[] = {"add_addsub_imm", "adds_addsub_imm", "sub_addsub_imm", "subs_addsub_imm",
                            "add_addsub_ext", "adds_addsub_ext", "sub_addsub_ext", "subs_addsub_ext",
                            "add_addsub_shift", "adds_addsub_shift", "sub_addsub_shift", "subs_addsub_shift",
                            "adc", "adcs", "adr", "adrp", "b_uncond"};
    std::string pcode_files_dir("/u/s/s/ssunny/dev-home/dyninst/dyninst-code/instructionAPI/ISA_ps/");

    Dyninst_aarch64::Driver driver;
    for(int fidx = 0; fidx < sizeof(fnames)/sizeof(char *); fidx++)
        driver.pcode_parse(pcode_files_dir + std::string(fnames[fidx]));
	//driver.pcode_parse(pcode_files_dir + std::string("adrp"));

    return 0;
}
