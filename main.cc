#include "driver.h"
#include "scanner.h"
#include <string>

int main() {
    std::string pcode_files_dir("/u/s/s/ssunny/dev-home/dyninst/dyninst-code/instructionAPI/ISA_ps/");

    Dyninst_aarch64::Driver driver;
    bool retVal = driver.pcode_parse(pcode_files_dir + std::string("adcs"));

    return 0;
}