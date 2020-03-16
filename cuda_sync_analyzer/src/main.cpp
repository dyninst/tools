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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] <<
            " <target mutated libcuda path> <livelocked program path>\n";
        return 1;
    }

    LocateCudaSynchronization scuda;
    std::vector<uint64_t> potentials;
    uint64_t syncAddr = scuda.FindLibcudaOffset(false);
    std::string newLibcuda(argv[1]);
    if (syncAddr == 0) { // temporary measure until driver on test machine is fixed
        potentials = scuda.IdentifySyncFunction();
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(std::string(argv[2]));
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
        {
            std::string libCudaPath = scuda.FindLibCuda().string();
            std::shared_ptr<BPatchBinary> bin = std::shared_ptr<BPatchBinary>(
                    new BPatchBinary(libCudaPath, true, newLibcuda));
            InstrSyncOffset instrSyncOffset(bin);
            instrSyncOffset.InsertInstr(syncAddr);
        }
        std::cout << "Saved instrumented binary to " << newLibcuda << std::endl;
        /*
        {
            std::shared_ptr<DyninstProcess> proc = LaunchApplicationByName(
                std::string("/nobackup/nisargs/diogenes-project/nohang_devsync"));
            std::cout << "Init nohang process" << std::endl;
            proc->RunCudaInit(newLibcuda);
            std::cout << "RunCudaInit" << std::endl;
            //InstrSyncOffset instrSyncOffset(proc);
            //instrSyncOffset.InsertInstr(syncAddr, newLibcuda);
            std::cout << "Run program until completion" << std::endl;
            proc->RunUntilCompleation();
        }
        */
    //}
}
