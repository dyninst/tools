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
    ret->LoadLibrary(std::string("libcuda.so.1"));
    return ret;
}

int main(void) {
    LocateCudaSynchronization scuda;
    std::vector<uint64_t> potentials;
    uint64_t syncAddr = scuda.FindLibcudaOffset(false);
    if (syncAddr == 0) {
        potentials = scuda.IdentifySyncFunction();
/*        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/hang_devsync"));
            proc->RunCudaInit();
            LaunchIdentifySync sync(proc);
            sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"), true, std::string("/lib/libFindSyncHelper.so"));
            proc->RunUntilCompleation();
            potentials.clear();
            syncAddr = sync.PostProcessing(potentials);
            if (potentials.size() > 1) {
                std::cout << "We have more than one possibility for sync function, picking lowest level one" << std::endl;
            }
            scuda.WriteSyncLocation(syncAddr);
        }
*/
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/hang_devsync"));
            proc->RunCudaInit();
            LaunchIdentifySync sync(proc);
            sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"), true, std::string("/lib/libFindSyncHelper.so"));
            proc->RunUntilCompleation();
            potentials.clear();
            syncAddr = sync.PostProcessing(potentials);
            if (potentials.size() > 1) {
                std::cout << "We have more than one possibility for sync function, picking lowest level one" << std::endl;
            }
            scuda.WriteSyncLocation(syncAddr);
        }
    }
 
    {
        potentials = scuda.IdentifySyncFunction();
        std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/nohang_devsync"));
        proc->RunCudaInit();
        InstrSyncOffset instrSyncOffset(proc);
        instrSyncOffset.InsertInstr(syncAddr);
        std::cout << "Run program until completion" << std::endl;
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
