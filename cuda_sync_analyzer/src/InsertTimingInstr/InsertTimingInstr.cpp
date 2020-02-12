#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

typedef std::chrono::high_resolution_clock hrc;

struct ExecTime {
    uint64_t id = 0;
    uint64_t duration = 0;
    uint64_t sync_duration = 0;
    uint64_t call_cnt = 0;
    const char *func_name;
};

// Shared ptr to vector of ExecTimes
typedef std::shared_ptr<std::vector<ExecTime> > ExecTimesPtr;

// class Aggregator {
// private:
//     std::mutex m;
//     uint64_t index = 0;
// public:
//     std::shared_ptr<std::vector<ExecTimesPtr> > aggregates;
//     Aggregator() {
//         aggregates = std::shared_ptr<std::vector<ExecTimesPtr> >(
//             new std::vector<ExecTimesPtr>(100));
//     }
//     void addVec(ExecTimesPtr& v) {
//         std::scoped_lock(m);
//         aggregates->at(index) = v;
//         index++;
//     }
//     size_t size() {
//         return index;
//     }
// };

// std::shared_ptr<Aggregator> agg;

// TODO: how to get size -
// 1. pass it as argument to entry instrumentation
// 2. insert it in libcuda and fetch it here
// 3. use constant value
thread_local ExecTime** exec_times = NULL;

// Maintain count of unresolved API entries
thread_local uint64_t stack_cnt = 0;
thread_local hrc::time_point api_entry, api_exit,
                             sync_entry, sync_exit;
thread_local uint64_t sync_total = 0;

std::atomic<bool> stop_timing(false);

extern "C" {
    /**
     * Post-execution actions
     */
    void DIOG_SAVE_INFO() {
        // std::cout << "atexit" << std::endl;
        // for (int i = 0; i < 1000; i++) {
        //     if (agg->aggregates->at(0)->at(i).id != 0) {
        //         std::cout << "agg: " << agg->aggregates->at(0)->at(i).func_name << std::endl;
        //     }
        // }

        // This is set to avoid instrumenting cuModuleUnload, etc.,
        // which are called after thread is destroyed
        stop_timing = true;

        std::ofstream outfile("InstrTimings.out");
        assert(outfile.good());

        // for (std::vector<ExecTime>::iterator it = exec_times->begin(); it != exec_times->end(); ++it) {
        //     if (it->id == 0) continue;
        //     outfile << it->func_name << " " << it->duration << " " << it->sync_duration << " " << it->call_cnt << std::endl;
        // }
        for (int i = 0; i < 1000; i++) {
            if (exec_times[i]->id == 0) continue;
            outfile << exec_times[i]->func_name << " " << exec_times[i]->duration
                    << " " << exec_times[i]->sync_duration << " "
                    << exec_times[i]->call_cnt << std::endl;
        }
    }

    /**
     * Perform initialization on the very first API entry
     * Add ptr to thread-local vector to a global array of ptrs
     */
    void DIOG_SignalStartInstra() {
        // std::cout << "Signal start of intrumentation" << std::endl;
        // if (!agg)
        //     agg = std::shared_ptr<Aggregator>(new Aggregator);
        if (!exec_times) {
            //exec_times = ExecTimesPtr(new std::vector<ExecTime>(1000));
            exec_times = (ExecTime **) malloc(sizeof(ExecTime *) * 1000);
            for (int i = 0; i < 1000; i++) {
                exec_times[i] = (ExecTime *) malloc(sizeof(ExecTime));
            }

            // agg->addVec(exec_times);
        }

        if (atexit(DIOG_SAVE_INFO) != 0)
            std::cerr << "Failed to register atexit function" << std::endl;
    }

    /**
     * API entry instrumentation
     * Increments stack_cnt, denoting number of public functions in the current call stack
     */
    void DIOG_API_ENTRY(uint64_t offset) {
        if (stop_timing) return;
        stack_cnt++;
        if (stack_cnt > 1) return; // 

        // std::cout << "-------Start timer" << std::endl;
        if (exec_times == NULL)
            DIOG_SignalStartInstra();

        api_entry = hrc::now();
    }

    /**
     * API exit instrumentation
     * Store instrumentation for the API in a thread-local vector
     */
    void DIOG_API_EXIT(uint64_t offset, uint64_t id, const char *name) {
        // std::cout << "id: " << id << std::endl;
        if (stop_timing) return;
        stack_cnt--;
        // stack_cnt > 0 means this API is called from within another API
        if (stack_cnt > 0) return;

        api_exit = hrc::now();
        // std::cout << "-------Stopped timer for " << name << ", id: " << id << std::endl;

        exec_times[id]->id = id;
        exec_times[id]->duration += std::chrono::duration<double, std::nano>(
            api_exit - api_entry).count();
        exec_times[id]->sync_duration += sync_total;
        exec_times[id]->call_cnt++;
        exec_times[id]->func_name = name;

        sync_total = 0; 
    }

    /**
     * Synchronization entry instrumentation
     */
    void DIOG_SYNC_ENTRY(uint64_t offset) {
        if (stop_timing) return;
        // Case when synchronization function is called by a non-public function
        if (stack_cnt == 0) return;
        // std::cout << "start sync ..." << std::endl;
        sync_entry = hrc::now();
    }

    /**
     * Synchronization exit instrumentation
     */
    void DIOG_SYNC_EXIT(uint64_t offset) {
        if (stop_timing) return;
        // std::cout << "Stop sync timer" << std::endl;
        // Case when synchronization function is called by a non-public function
        if (stack_cnt == 0) return;
        sync_exit = hrc::now();
        // std::cout << "stopped sync" << std::endl;

        sync_total += std::chrono::duration<double, std::nano>(
            sync_exit - sync_entry).count();
    }
}
