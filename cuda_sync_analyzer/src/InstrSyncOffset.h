#pragma once

#include <cassert>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "BPatch_function.h"
#include "BPatch_object.h"
#include "BPatch_point.h"
#include "BPatch_snippet.h"

#include "DyninstProcess.h"
#include "DynOpsClass.h"
#include "DyninstMutatee.h"

/* 
 * Class to insert timing instrumentation into given offset
*/
class InstrSyncOffset {
private:
    std::shared_ptr<DyninstMutatee> _mutatee;
public:
    InstrSyncOffset(std::shared_ptr<DyninstMutatee> mutatee);
    void InsertInstr(uint64_t syncOffset);
    std::vector<uint64_t> getOffsets(
        const std::unordered_map<uint64_t, BPatch_function *>& funcMap);
};
