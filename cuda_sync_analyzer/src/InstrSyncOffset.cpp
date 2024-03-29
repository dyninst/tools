#include "InstrSyncOffset.h"

InstrSyncOffset::InstrSyncOffset(std::shared_ptr<DyninstMutatee> mutatee) : _mutatee(mutatee) { 

}

/**
 * Compute vector of offsets for public CUDA functions
 */
std::vector<uint64_t> InstrSyncOffset::getOffsets(
        const std::unordered_map<uint64_t, BPatch_function *> &funcMap) {
    vector<uint64_t> offsets;
    offsets.reserve(443);
    for (auto const &f: funcMap) {
        if (f.second->getName().compare(0, 2, std::string("cu")) == 0) {
            offsets.push_back(f.first);
        }
    }
    return offsets;
}

void InstrSyncOffset::InsertInstr(uint64_t syncOffset) {
    std::shared_ptr<DynOpsClass> ops = _mutatee->ReturnDynOps();
    BPatch_object *instrLib = _mutatee->LoadLibrary(
            std::string(LOCAL_INSTALL_PATH) + std::string("/lib/libCudaProfInstr.so"));

    std::vector<BPatch_function *> cEntry = ops->FindFuncsByName(
            _mutatee->GetAddressSpace(), std::string("CPROF_API_ENTRY"), instrLib);
    std::vector<BPatch_function *> cExit = ops->FindFuncsByName(
            _mutatee->GetAddressSpace(), std::string("CPROF_API_EXIT"), instrLib);
    assert(cEntry.size() == 1 && cExit.size() == 1);

    BPatch_object *libCuda = NULL;
    // Required only for a process since offset needs to be calculated relative to libcuda
    BPatch_process *appProc = dynamic_cast<BPatch_process *>(_mutatee->GetAddressSpace());
    if (appProc) {
        std::cout << "Loading libcuda to compute offset->BPatch_function map" << std::endl;
        libCuda = _mutatee->LoadLibrary(std::string("libcuda.so.1"));
    }
    std::unordered_map<uint64_t, BPatch_function *> funcMap = ops->GetFuncMap(
            _mutatee->GetAddressSpace(), libCuda);
    vector<uint64_t> offsets = getOffsets(funcMap);

    uint64_t id = 1;
    for (auto offset : offsets) {
        if (funcMap.find(offset) != funcMap.end() || offset < 0x200000){
            std::cout << "Inserting Instrumentation into function at offset = "
                << std::hex << offset << std::endl;

            auto f = funcMap[offset];

            std::vector<BPatch_snippet*> entryArgs;
            entryArgs.push_back(new BPatch_constExpr(offset));

            std::vector<BPatch_snippet*> exitArgs;
            exitArgs.push_back(new BPatch_constExpr(offset));
            exitArgs.push_back(new BPatch_constExpr(id));
            exitArgs.push_back(new BPatch_constExpr(f->getName().c_str()));

            InsertSnippet(f, cEntry, cExit, entryArgs, exitArgs);
            // _mutatee->BeginInsertionSet();

            // std::vector<BPatch_snippet*> exitArgs;
            // exitArgs.push_back(new BPatch_constExpr(offset));

            // std::vector<BPatch_snippet*> entryArgs(exitArgs);
            // entryArgs.push_back(new BPatch_constExpr(f->getName().c_str()));

            // BPatch_funcCallExpr entryExpr(*cEntry[0], entryArgs);
            // BPatch_funcCallExpr exitExpr(*cExit[0], exitArgs);

            // std::vector<BPatch_point*> *entry = f->findPoint(BPatch_locEntry);
            // std::vector<BPatch_point*> *exit = f->findPoint(BPatch_locExit);

            // _mutatee->GetAddressSpace()->insertSnippet(entryExpr,*entry);
        
            // std::vector<BPatch_point*> prev;
            // prev.push_back(ops->FindPreviousPoint((*exit)[0], _mutatee->GetAddressSpace()));
            // _mutatee->GetAddressSpace()->insertSnippet(exitExpr,prev);
        }
        else {
            std::cerr << "Offset " << std::hex << offset << " not found!" << std::endl;
        }
        id++;
    }

    std::vector<BPatch_function *> cSyncEntry = ops->FindFuncsByName(
            _mutatee->GetAddressSpace(), std::string("CPROF_SYNC_ENTRY"), instrLib);
    std::vector<BPatch_function *> cSyncExit = ops->FindFuncsByName(
            _mutatee->GetAddressSpace(), std::string("CPROF_SYNC_EXIT"), instrLib);
    assert(cSyncEntry.size() == 1 && cSyncExit.size() == 1);

    if (funcMap.find(syncOffset) != funcMap.end() || syncOffset < 0x200000) {
        std::cout << "Inserting Instrumentation into function at offset = "
                  << std::hex << syncOffset << std::endl;
        // InsertSnippet(syncOffset, 0, funcMap[syncOffset], cSyncEntry, cSyncExit);
        std::vector<BPatch_snippet *> entryArgs;
        entryArgs.push_back(new BPatch_constExpr(syncOffset));

        std::vector<BPatch_snippet *> exitArgs;
        exitArgs.push_back(new BPatch_constExpr(syncOffset));
        // exitArgs.push_back(new BPatch_constExpr(id));
        InsertSnippet(funcMap[syncOffset], cSyncEntry, cSyncExit, entryArgs, exitArgs);
    }
    else
        std::cerr << "Offset " << std::hex << syncOffset << " not found!" << std::endl;
}

/**
 * Insert given BPatch_functions on function entry/exit locations
 */
void InstrSyncOffset::InsertSnippet(BPatch_function *f,
        std::vector<BPatch_function *> cEntry, std::vector<BPatch_function *> cExit,
        std::vector<BPatch_snippet *> entryArgs, std::vector<BPatch_snippet *> exitArgs) {
    _mutatee->BeginInsertionSet();

    BPatch_funcCallExpr entryExpr(*cEntry[0], entryArgs);
    BPatch_funcCallExpr exitExpr(*cExit[0], exitArgs);

    std::vector<BPatch_point *> *entry = f->findPoint(BPatch_locEntry);
    std::vector<BPatch_point *> *exit = f->findPoint(BPatch_locExit);

    _mutatee->GetAddressSpace()->insertSnippet(entryExpr,*entry);

    std::shared_ptr<DynOpsClass> ops = _mutatee->ReturnDynOps();
    std::vector<BPatch_point *> prev;
    prev.push_back(ops->FindPreviousPoint((*exit)[0], _mutatee->GetAddressSpace()));
    _mutatee->GetAddressSpace()->insertSnippet(exitExpr,prev);
}
