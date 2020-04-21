#include "FindCudaSync.h"
#include "DyninstProcess.h"
#include "InstrSyncOffset.h"
#include "LocateCudaSynchronization.h"
#include "LaunchIdentifySync.h"

std::shared_ptr<DyninstProcess> LaunchApplicationByName(std::string name) {
    std::shared_ptr<DyninstProcess> ret(new DyninstProcess(name));
    assert(ret->LaunchProcess() != NULL);

    // Load libcuda.so into the address space of the process
    BPatch_process *bproc = (BPatch_process *) ret->GetAddressSpace();
    assert(bproc->isStopped() == true);
    //ret->LoadLibrary(std::string("libcuda.so.1"));
    return ret;
}

uint64_t CSA_FindSyncAddress(std::string & cudaPath) {
    LocateCudaSynchronization scuda;
    std::vector<uint64_t> potentials;
    
    uint64_t syncAddr = scuda.FindLibcudaOffset(false);
    if (syncAddr == 0) {
        potentials = scuda.IdentifySyncFunction();
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(
                    std::string(LOCAL_INSTALL_PATH) + std::string("/bin/hang_devsync"));
            proc->RunCudaInit();
            LaunchIdentifySync sync(proc);
            sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"),
                    true, std::string("/lib/libFindSyncHelper.so"));
            proc->RunUntilCompleation();
            potentials.clear();
            syncAddr = sync.PostProcessing(potentials);
            if (potentials.size() > 1) {
                std::cout << "We have more than one possibility for sync function,"
                   << " picking lowest level one" << std::endl;
            }
            scuda.WriteSyncLocation(syncAddr);
        }
    }
    cudaPath = scuda.FindLibCuda().string();

    return syncAddr;
}