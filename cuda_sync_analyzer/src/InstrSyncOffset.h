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

class InstrSyncOffset {
    private:
        std::shared_ptr<DyninstProcess> _proc;
    public:
        InstrSyncOffset(std::shared_ptr<DyninstProcess> proc);
        void InsertInstr(uint64_t syncOffset);
};
