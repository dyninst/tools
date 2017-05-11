/*
 * See the dyninst/COPYRIGHT file for copyright information.
 *
 * We provide the Paradyn Tools (below described as "Paradyn")
 * on an AS IS basis, and do not warrant its validity or performance.
 * We reserve the right to update, modify, or discontinue this
 * software at any time.  We shall have no obligation to supply such
 * updates or modifications or any other form of support to you.
 *
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "driver.h"
#include "scanner.h"
#include <sys/stat.h>

bool file_exists(const char *fname) {
    struct stat buf;
    return stat(fname, &buf) == 0;
}

int main() {

    /*
     * List of files that need to be parsed. Currently roughly organized categorically.
     *
     * This would ideally contain all files under ISA_ps. However, currently, only a subset is included since I wanted to be selective about
     * what to parse. It is possible to just include all files and later choose which ones to parse - shouldn't be too hard to implement; this
     * solution works fine though for now.
     *
     * Even in this subset, comment the ones you don't need to filter parsing further.
     */
    const char *fnames[] = {/*"add_addsub_imm", "adds_addsub_imm", "sub_addsub_imm", "subs_addsub_imm",
                            "add_addsub_ext", "adds_addsub_ext", "sub_addsub_ext", "subs_addsub_ext",
                            "add_addsub_shift", "adds_addsub_shift", "sub_addsub_shift", "subs_addsub_shift",
                            "adc", "adcs", "adr", "adrp", "tbz", "tbnz", "b_uncond", "b_cond", "br", "blr", "bl", "cbz", "cbnz",
                            "cmp_subs_addsub_imm", "cmp_subs_addsub_ext", "cmp_subs_addsub_shift",
                            "cmn_adds_addsub_imm", "cmn_adds_addsub_ext", "cmn_adds_addsub_shift",
                            "ccmn_reg", "ccmn_imm",
                            "ldr_imm_gen", "str_imm_gen", "ldrb_imm", "strb_imm", "ldrh_imm", "ldrsb_imm", "ldrsh_imm", "ldrsw_imm", "strh_imm",
                            "ldr_reg_gen", "ldrb_reg", "ldrh_reg", "ldrsb_reg", "ldrsh_reg", "ldrsw_reg", "str_reg_gen", "strb_reg", "strh_reg",
                            "ldr_lit_gen", "ldrsw_lit",
                            "ubfm", "uxtb_ubfm", "uxth_ubfm", "ubfiz_ubfm", "ubfx_ubfm", "sbfm", "sxth_sbfm", "sxtb_sbfm", "sbfiz_sbfm", "sbfx_sbfm", "sxtw_sbfm",
                            "movz", "mov_movz", "movn", "mov_movn", "movk",
                            "orr_log_shift", "mov_orr_log_shift", "mov_orr_log_imm", "orn_log_shift", "orr_log_imm",
                            "and_log_imm", "and_log_shift", "ands_log_imm", "ands_log_shift", "eor_log_shift", "eor_log_imm", "eon",
                            "lsl_ubfm", "lsr_ubfm", "asr_sbfm",
                            "bfm", "bfxil_bfm", "bfi_bfm", "bic_log_shift", "bics", "stp_gen", "ldp_gen", "stnp_gen", "ldpsw", "ldnp_gen", "stnp_gen",
                            "ldtr", "ldtrb", "ldtrh", "ldtrsb", "ldtrsh", "sttr", "sttrb", "sttrh",
                            "ldur_gen", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw", "sturb", "sturh", "stur_gen",
                            "asr_asrv", "asrv", "lsl_lslv", "lslv", "lsr_lsrv", "lsrv", "ror_rorv", "rorv"
                            "tst_ands_log_imm", "tst_ands_log_shift", "sbc", "sbcs", "ngc_sbc", "ngcs_sbcs", "neg_sub_addsub_shift", "negs_subs_addsub_shift",
                            "mvn_orn_log_shift", "mov_add_addsub_imm",
                            "csinv", "csinc", "csneg", "csel",
                            "cls_int", "clz_int",
                            "madd", "msub", "mneg_msub", "mul_madd", "smaddl", "smsubl", "smnegl_smsubl","smulh", "smull_smaddl","umaddl", "umsubl", "umnegl_umsubl", "umulh", "umull_umaddl",
                            "ldar", "ldarb", "ldarh", "stlr", "stlrb", "stlrh",
                            "udiv", */"sdsiv"};

    /** Root folder containing the pseudocode files created by the pseudocode extractor script. Change as necessary. */
    std::string pcode_files_dir("/u/s/s/ssunny/dev-home/dyninst/dyninst-code/instructionAPI/ISA_ps/");

    /** Iterate over all files in the list above and parse them. */
    Dyninst_aarch64::Driver driver;
    std::map<const char *, bool> notExists;
    for(int fidx = 0; fidx < sizeof(fnames)/sizeof(char *); fidx++) {
        if(file_exists(fnames[fidx]))
            driver.pcode_parse(pcode_files_dir + std::string(fnames[fidx]));
        else
            notExists[fnames[fidx]] = true;
    }

    /** For each file above, output the iproc_set statement for the corresponding instruction.
     * This needs to go into the iproc_init method of the Dispatcher. */
    for(int idx = 0; idx < sizeof(fnames)/sizeof(char *); idx++)
        if(!notExists.count(fnames[idx]))
            std::cout<<"iproc_set (rose_aarch64_op_"<<fnames[idx]<<", new ARM64::IP_"<<fnames[idx]<<"_execute);"<<std::endl;

    if(notExists.size()) {
        std::cout<<std::endl;
        std::cout<<"### Some files not found:"<<std::endl;
        for (std::map<const char *, bool>::iterator itr = notExists.begin(); itr != notExists.end(); itr++) {
            std::cout << "Could not find file " << itr->first << "." << std::endl;
        }
    }

    return 0;
}

