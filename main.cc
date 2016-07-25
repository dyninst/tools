#include "driver.h"
#include "scanner.h"

int main() {
    const char *fnames[] = {/*"add_addsub_imm", "adds_addsub_imm", "sub_addsub_imm", "subs_addsub_imm",
                            "add_addsub_ext", "adds_addsub_ext", "sub_addsub_ext", "subs_addsub_ext",
                            "add_addsub_shift", "adds_addsub_shift", "sub_addsub_shift", "subs_addsub_shift",
                            "adc", "adcs", "adr", "adrp", "b_uncond", "b_cond", "br", "blr", "bl", "cbz", "cbnz", "tbz", "tbnz"/*,
                            "cmp_subs_addsub_imm", "cmp_subs_addsub_ext", "cmp_subs_addsub_shift",
                            "cmn_adds_addsub_imm", "cmn_adds_addsub_ext", "cmn_adds_addsub_shift",
                            "ccmn_reg", "ccmn_imm"*/
                            "ldr_imm_gen"};
    std::string pcode_files_dir("/u/s/s/ssunny/dev-home/dyninst/dyninst-code/instructionAPI/ISA_ps/");

    Dyninst_aarch64::Driver driver;
    for(int fidx = 0; fidx < sizeof(fnames)/sizeof(char *); fidx++)
        driver.pcode_parse(pcode_files_dir + std::string(fnames[fidx]));
	//driver.pcode_parse(pcode_files_dir + std::string("adrp"));

    for(int idx = 0; idx < sizeof(fnames)/sizeof(char *); idx++)
        std::cout<<"iproc_set(rose_aarch64_op_"<<fnames[idx]<<", new ARM64::IP_"<<fnames[idx]<<"_execute);"<<std::endl;

    return 0;
}
/*boolean wb_unknown = FALSE;
boolean rt_unknown = FALSE;

if memop == MemOp_LOAD && wback && n == t && n != 31 then
    c = ConstrainUnpredictable(Unpredictable_WBOVERLAPLD);
    assert c IN {Constraint_WBSUPPRESS, Constraint_UNKNOWN, Constraint_UNDEF, Constraint_NOP};
    case c of
        when Constraint_WBSUPPRESS wback = FALSE;       // writeback is suppressed
        when Constraint_UNKNOWN    wb_unknown = TRUE;   // writeback is UNKNOWN
        when Constraint_UNDEF      UnallocatedEncoding();
        when Constraint_NOP        EndOfInstruction();
end

if memop == MemOp_STORE && wback && n == t && n != 31 then
    c = ConstrainUnpredictable(Unpredictable_WBOVERLAPST);
    assert c IN {Constraint_NONE, Constraint_UNKNOWN, Constraint_UNDEF, Constraint_NOP};
    case c of
        when Constraint_NONE       rt_unknown = FALSE;  // value stored is original value
        when Constraint_UNKNOWN    rt_unknown = TRUE;   // value stored is UNKNOWN
        when Constraint_UNDEF      UnallocatedEncoding();
        when Constraint_NOP        EndOfInstruction();
end

if n == 31 then
    if memop != MemOp_PREFETCH then CheckSPAlignment();
    address = SP[];
else
    address = X[n];
end

if ! postindex then
    address = address + offset;
end

case memop of
    when MemOp_STORE
        if rt_unknown then
            data = bits(datasize) UNKNOWN;
        else
            data = X[t];
        Mem[address, datasize DIV 8, acctype] = data;
        end

    when MemOp_LOAD
        data = Mem[address, datasize DIV 8, acctype];
        if signed then
            X[t] = SignExtend(data, regsize);
        else
            X[t] = ZeroExtend(data, regsize);
        end

    when MemOp_PREFETCH
        Prefetch(address, t<4:0>);

if wback then
    if wb_unknown then
        address = bits(64) UNKNOWN;
    elsif postindex then
        address = address + offset;
    if n == 31 then
        SP[] = address;
    else
        X[n] = address;
end
*/
