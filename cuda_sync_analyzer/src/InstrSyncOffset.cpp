#include "InstrSyncOffset.h"

InstrSyncOffset::InstrSyncOffset(std::shared_ptr<DyninstProcess> proc) : _proc(proc) { 

}

void InstrSyncOffset::InsertInstr(uint64_t syncOffset) {
    std::shared_ptr<DynOpsClass> ops = _proc->ReturnDynOps();
    BPatch_object * instrLib = _proc->LoadLibrary(std::string(LOCAL_INSTALL_PATH) + std::string("/lib/libInsertTimingInstr.so"));

    std::vector<BPatch_function *> cEntry = ops->FindFuncsByName(_proc->GetAddressSpace(), std::string("START_TIMER_INSTR"), instrLib);
    std::vector<BPatch_function *> cExit = ops->FindFuncsByName(_proc->GetAddressSpace(), std::string("STOP_TIMER_INSTR"), instrLib);
    assert(cEntry.size() == 1 && cExit.size() == 1);

    std::unordered_map<uint64_t, BPatch_function *> funcMap = _proc->GetFuncMap();
    if (funcMap.find(syncOffset) != funcMap.end() || syncOffset < 0x200000){
        std::cout << "Inserting Instrumentation into function at offset = "
            << std::hex << syncOffset << std::endl;
        _proc->BeginInsertionSet();

        std::vector<BPatch_snippet*> recordArgs;
        recordArgs.push_back(new BPatch_constExpr(syncOffset));
        BPatch_funcCallExpr entryExpr(*cEntry[0], recordArgs);
        BPatch_funcCallExpr exitExpr(*cExit[0], recordArgs);

        auto f = funcMap[syncOffset];
        std::vector<BPatch_point*> * entry = f->findPoint(BPatch_locEntry);
        std::vector<BPatch_point*> * exit = f->findPoint(BPatch_locExit);

        _proc->GetAddressSpace()->insertSnippet(entryExpr,*entry);
        
        std::vector<BPatch_point*> prev;
        prev.push_back(_proc->FindPreviousPoint((*exit)[0]));
        _proc->GetAddressSpace()->insertSnippet(exitExpr,prev);
    }
    else {
        std::cerr << "Offset " << std::hex << syncOffset << " not found!" << std::endl;
    }
}
