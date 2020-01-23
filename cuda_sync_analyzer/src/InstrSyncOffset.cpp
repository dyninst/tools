#include "InstrSyncOffset.h"

InstrSyncOffset::InstrSyncOffset(std::shared_ptr<DyninstMutatee> mutatee) : _mutatee(mutatee) { 

}

void InstrSyncOffset::InsertInstr(uint64_t syncOffset) {
    std::shared_ptr<DynOpsClass> ops = _mutatee->ReturnDynOps();
    BPatch_object * instrLib = _mutatee->LoadLibrary(
            std::string(LOCAL_INSTALL_PATH) + std::string("/lib/libInsertTimingInstr.so"));

    std::vector<BPatch_function *> cEntry = ops->FindFuncsByName(
            _mutatee->GetAddressSpace(), std::string("START_TIMER_INSTR"), instrLib);
    std::vector<BPatch_function *> cExit = ops->FindFuncsByName(
            _mutatee->GetAddressSpace(), std::string("STOP_TIMER_INSTR"), instrLib);
    assert(cEntry.size() == 1 && cExit.size() == 1);

    BPatch_object * libCuda = NULL;
    // Required only for a process since offset needs to be calculated relative to libcuda
    BPatch_process * appProc = dynamic_cast<BPatch_process *>(_mutatee->GetAddressSpace());
    if (appProc) {
        std::cout << "Loading libcuda to compute offset->BPatch_function map" << std::endl;
        libCuda = _mutatee->LoadLibrary(std::string("libcuda.so.1"));
    }
    std::unordered_map<uint64_t, BPatch_function *> funcMap = ops->GetFuncMap(
            _mutatee->GetAddressSpace(), libCuda);
    if (funcMap.find(syncOffset) != funcMap.end() || syncOffset < 0x200000){
        std::cout << "Inserting Instrumentation into function at offset = "
            << std::hex << syncOffset << std::endl;
        _mutatee->BeginInsertionSet();

        std::vector<BPatch_snippet*> recordArgs;
        recordArgs.push_back(new BPatch_constExpr(syncOffset));
        BPatch_funcCallExpr entryExpr(*cEntry[0], recordArgs);
        BPatch_funcCallExpr exitExpr(*cExit[0], recordArgs);

        auto f = funcMap[syncOffset];
        std::vector<BPatch_point*> * entry = f->findPoint(BPatch_locEntry);
        std::vector<BPatch_point*> * exit = f->findPoint(BPatch_locExit);

        _mutatee->GetAddressSpace()->insertSnippet(entryExpr,*entry);
        
        std::vector<BPatch_point*> prev;
        prev.push_back(ops->FindPreviousPoint((*exit)[0], _mutatee->GetAddressSpace()));
        _mutatee->GetAddressSpace()->insertSnippet(exitExpr,prev);
    }
    else {
        std::cerr << "Offset " << std::hex << syncOffset << " not found!" << std::endl;
    }
}
