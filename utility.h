//
// Created by ssunny on 7/21/16.
//

#ifndef CURRENT_UTILITY_H
#define CURRENT_UTILITY_H

namespace Dyninst_aarch64 {

    enum Constraint {
        // General:
                Constraint_NONE, Constraint_UNKNOWN,
                Constraint_UNDEF, Constraint_NOP,
                Constraint_TRUE, Constraint_FALSE,
                Constraint_DISABLED,
        // Load-store:
                Constraint_WBSUPPRESS, Constraint_FAULT,
        // IPA too large
                Constraint_FORCE, Constraint_FORCENOSLCHECK
    };


    enum Unpredictable {
        // Writeback/transfer register overlap (load):
                Unpredictable_WBOVERLAPLD,
        // Writeback/transfer register overlap (store):
                Unpredictable_WBOVERLAPST,
        // Load Pair transfer register overlap:
                Unpredictable_LDPOVERLAP,
        // Store-exclusive base/status register overlap
                Unpredictable_BASEOVERLAP,
        // Store-exclusive data/status register overlap
                Unpredictable_DATAOVERLAP,
        // Load-store alignment checks:
                Unpredictable_DEVPAGE2,
        // Instruction fetch from Device memory
                Unpredictable_INSTRDEVICE,
        // Reserved MAIR value
                Unpredictable_RESMAIR,
        // Reserved TEX:C:B value
                Unpredictable_RESTEXCB,
        // Reserved PRRR value
                Unpredictable_RESPRRR,
        // Reserved DACR field
                Unpredictable_RESDACR,
        // Reserved VTCR.S value
                Unpredictable_RESVTCRS,
        // Reserved TCR.TnSZ valu
                Unpredictable_RESTnSZ,
        // IPA size exceeds PA size
                Unpredictable_LARGEIPA,
        // Syndrome for a known-passing conditional A32 instruction
                Unpredictable_ESRCONDPASS,
        // Illegal State exception: zero PSTATE.IT
                Unpredictable_ILZEROIT,
        // Illegal State exception: zero PSTATE.T
                Unpredictable_ILZEROT,
        // Debug: prioritization of Vector Catch
                Unpredictable_BPVECTORCATCHPRI,
        // Debug Vector Catch: match on 2nd halfword
                Unpredictable_VCMATCHHALF,
        // Debug watchpoints: non-zero MASK and non-ones BAS
                Unpredictable_WPMASKANDBAS,
        // Debug watchpoints: non-contiguous BAS
                Unpredictable_WPBASCONTIGUOUS,
        // Debug watchpoints: reserved MASK
                Unpredictable_RESWPMASK,
        // Debug watchpoints: non-zero MASKed bits of address
                Unpredictable_WPMASKEDBITS,
        // Debug breakpoints and watchpoints: reserved control bits
                Unpredictable_RESBPWPCTRL,
        // Debug breakpoints: not implemented
                Unpredictable_BPNOTIMPL,
        // Debug breakpoints: reserved type
                Unpredictable_RESBPTYPE,
        // Debug breakpoints: not-context-aware breakpoint
                Unpredictable_BPNOTCTXCMP,
        // Debug breakpoints: match on 2nd halfword of instruction
                Unpredictable_BPMATCHHALF,
        // Debug breakpoints: mismatch on 2nd halfword of instruction
                Unpredictable_BPMISMATCHHALF,
        // Debug: restart to a misaligned AArch32 PC value
                Unpredictable_RESTARTMISALIGNPC,
        // Debug: restart to a not-zero-extended AArch32 PC value
                Unpredictable_RESTARTZEROUPPERPC,
        // Zero top 32 bits of X registers in AArch32 state:
                Unpredictable_ZEROUPPER,
        // Zero top 32 bits of PC on illegal return to AArch32 state
                Unpredictable_ERETZEROUPPERPC,
        // SMC disabled
                Unpredictable_SMD,
        // To be determined -- THESE SHOULD BE RESOLVED (catch-all)
                Unpredictable_TBD
    };


}

#endif //CURRENT_UTILITY_H
