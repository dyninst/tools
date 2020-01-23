#include "DyninstProcess.h"
#include "InstrSyncOffset.h"
#include "LocateCudaSynchronization.h"
#include "LaunchIdentifySync.h"
//#include "InstrLibCuda.h"

std::shared_ptr<DyninstProcess> LaunchApplicationByName(std::string name) {
    std::shared_ptr<DyninstProcess> ret(new DyninstProcess(name));
    assert(ret->LaunchProcess() != NULL);

    // Load libcuda.so into the address space of the process
    BPatch_process *bproc = (BPatch_process *) ret->GetAddressSpace();
    assert(bproc->isStopped() == true);
    //ret->LoadLibrary(std::string("libcuda.so.1"));
    return ret;
}

int main(void) {
    LocateCudaSynchronization scuda;
    std::vector<uint64_t> potentials;
    uint64_t syncAddr = scuda.FindLibcudaOffset(false);
    std::string newLibcuda("/nobackup/nisargs/newlibcuda.so");
    if (syncAddr == 0) {
        potentials = scuda.IdentifySyncFunction();
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/hang_devsync"));
            proc->RunCudaInit();
            LaunchIdentifySync sync(proc);
            sync.InsertAnalysis(potentials, std::string("cudaDeviceSynchronize"), true, std::string("/lib/libFindSyncHelper.so"));
            proc->RunUntilCompleation();
            potentials.clear();
            syncAddr = sync.PostProcessing(potentials);
            if (potentials.size() > 1) {
                std::cout << "[SyncTesting::IndentifySyncFunction] We have more than one possibility for sync function, picking lowest level one" << std::endl;
            }
            scuda.WriteSyncLocation(syncAddr);
        }
    }
        //std::unordered_map<uint64_t, uint64_t> idToOffset;
        {
            //std::shared_ptr<DyninstProcess> libCudaBin = std::shared_ptr<DyninstProcess>(new DyninstProcess(libCudaPath));
            std::string libCudaPath = scuda.FindLibCuda().string();
            std::shared_ptr<BPatchBinary> bin = std::shared_ptr<BPatchBinary>(new BPatchBinary(libCudaPath, true, newLibcuda));
            std::cout << "Init bpatch binary" << std::endl;
            InstrSyncOffset instrSyncOffset(bin);
            std::cout << "Mutator object created" << std::endl;
            instrSyncOffset.InsertInstr(syncAddr, libCudaPath);
            //idToOffset = instrLibCuda.GetIdToOffset();
            std::cout << "Instrumentation inserted into libcuda" << std::endl;
        }
        //assert(idToOffset.size() > 0);
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string("/nobackup/nisargs/diogenes-project/nohang_devsync"));
            std::cout << "Init nohang process" << std::endl;
            proc->RunCudaInit(newLibcuda);
            std::cout << "RunCudaInit" << std::endl;
            //InstrSyncOffset instrSyncOffset(proc);
            //instrSyncOffset.InsertInstr(syncAddr, newLibcuda);
            std::cout << "Run program until completion" << std::endl;
            proc->RunUntilCompleation();
        }
    //}
}
