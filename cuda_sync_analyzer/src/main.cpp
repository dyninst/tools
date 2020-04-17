#include "DyninstProcess.h"
#include "InstrSyncOffset.h"
#include "LocateCudaSynchronization.h"
#include "LaunchIdentifySync.h"
#include "FindCudaSync.h"


int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target directory>\n";
        return 1;
    }
    std::string cudaPath;

    uint64_t syncAddr = CSA_FindSyncAddress(cudaPath);

    std::string newLibcuda(std::string(argv[1]) + std::string("/libcuda.so.1"));
    std::shared_ptr<BPatchBinary> bin = std::shared_ptr<BPatchBinary>(
            new BPatchBinary(cudaPath, true, newLibcuda));
    InstrSyncOffset instrSyncOffset(bin);
    instrSyncOffset.InsertInstr(syncAddr);

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
