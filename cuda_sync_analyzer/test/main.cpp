#include "DyninstProcess.h"
#include "LocateCudaSynchronization.h"
#include "LaunchIdentifySync.h"
//#include "InstrCudaFuncs.h"

std::shared_ptr<DyninstProcess> LaunchApplicationByName(std::string name, bool debug) {
    std::shared_ptr<DyninstProcess> ret(new DyninstProcess(name, debug));
    assert(ret->LaunchProcess() != NULL);

    // Load libcuda.so into the address space of the process
    BPatch_process *bproc = (BPatch_process *) ret->GetAddressSpace();
    assert(bproc->isStopped() == true);
    ret->LoadLibrary(std::string("libcuda.so.1"));
    return ret;
}

int main(void) {
    LocateCudaSynchronization scuda;
    std::vector<uint64_t> potentials;
    if (scuda.FindLibcudaOffset(false) == 0) {
        //return 1;
        potentials = scuda.IdentifySyncFunction();
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/hang_devsync"), false);
            proc->RunCudaInit();
            LaunchIdentifySync sync(proc);
            sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"), true, std::string("/lib/libFindSyncHelper.so"));
            proc->RunUntilCompleation();
            potentials.clear();
            uint64_t addr = sync.PostProcessing(potentials);
            if (potentials.size() > 1) {
                std::cout << "[SyncTesting::IndentifySyncFunction] We have more than one possibility for sync function, picking lowest level one" << std::endl;
            }
            scuda.WriteSyncLocation(addr);
        }
    }

    {
        potentials = scuda.IdentifySyncFunction();
        std::cout << "Executing actual program" << std::endl;
        std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/nohang_devsync"), false);
        proc->RunCudaInit();
        LaunchIdentifySync sync(proc);
        //InstrCudaFuncs instrFuncs(proc);
        sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"), true, std::string("/lib/libInsertTimingInstr.so"));
        proc->RunUntilCompleation();
        /*
        potentials.clear();
        uint64_t addr = sync.PostProcessing(potentials);
        if (potentials.size() > 1) {
            std::cout << "[SyncTesting::IndentifySyncFunction] We have more than one possibility for sync function, picking lowest level one" << std::endl;
        }
        scuda.WriteSyncLocation(addr);
        */
    }

}
