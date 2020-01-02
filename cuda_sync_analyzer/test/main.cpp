#include "DyninstProcess.h"
#include "LocateCudaSynchronization.h"
#include "LaunchIdentifySync.h"

std::shared_ptr<DyninstProcess> LaunchApplicationByName(std::string name, bool debug) {
    std::shared_ptr<DyninstProcess> ret(new DyninstProcess(name, debug));
    assert(ret->LaunchProcess() != NULL);

    // Load libcuda.so into the address space of the process
    ret->LoadLibrary(std::string("libcuda.so.1"));
    return ret;
}

int main(void) {
    LocateCudaSynchronization scuda;
    if (scuda.FindLibcudaOffset(false) != 0)
        return 1;
    std::vector<uint64_t> potentials = scuda.IdentifySyncFunction();
    {
        std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/hang_devsync"), false);
        proc->RunCudaInit();
        LaunchIdentifySync sync(proc);
        sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"), true);
        proc->RunUntilCompleation();
        potentials.clear();
        uint64_t addr = sync.PostProcessing(potentials);
        if (potentials.size() > 1) {
            std::cout << "[SyncTesting::IndentifySyncFunction] We have more than one possibility for sync function, picking lowest level one" << std::endl;
        }
        scuda.WriteSyncLocation(addr);
    }
}
