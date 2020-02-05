#include <atomic>
#include <chrono>
#include <unordered_map>
#include <vector>
#include <stack>
#include <cassert>
#include <iostream>
#include <fstream>
#include <memory>
#include <cstdlib>

typedef std::chrono::high_resolution_clock hrc;

struct ExecTime {
    uint64_t id;
    const char *func_name;
    hrc::time_point start_time;
    hrc::time_point end_time;
    uint64_t duration;
    uint64_t sync_duration = 0;
    uint64_t c_cnt = 0;
};

struct SyncTime {
    uint64_t id;
    hrc::time_point start_time;
    hrc::time_point end_time;
    uint64_t duration;
};

typedef std::shared_ptr<ExecTime> ExecTimeSPtr;

std::unique_ptr<std::vector<ExecTimeSPtr > > exec_times;

// Maintain stack of unresolved calls
thread_local std::unique_ptr<std::unordered_map<uint64_t, std::stack<ExecTimeSPtr > > > unresolved;
thread_local std::vector<SyncTime> sync_times;
std::atomic<bool> stop_timing(false);

extern "C" {
    void SAVE_INSTR_TIMES() {
        // std::cout << "atexit" << std::endl;
        stop_timing = true;
        std::ofstream outfile("InstrTimings.out");
        assert(outfile.good());
        std::unordered_map<std::string, ExecTime> aggregate_times;

        //outfile << "Function\t\tTime (ns)" << std::endl;
        for (std::vector<ExecTimeSPtr >::iterator it = exec_times->begin(); it != exec_times->end(); ++it) {
            auto record = it->get();
            std::string func_name = record->func_name;
            // outfile << record->func_name << " " << std::hex << record->id << " "
            //     << std::dec << record->duration << " ns" << std::endl;
            if (aggregate_times.find(func_name) == aggregate_times.end()) {
                ExecTime e;
                e.func_name = record->func_name;
                e.id = record->id;
                e.duration = 0;
                e.sync_duration = 0;
                aggregate_times[func_name] = e;
            }
            aggregate_times[func_name].duration += record->duration;
            aggregate_times[func_name].sync_duration += record->sync_duration;
            aggregate_times[func_name].c_cnt++;
        }

        for (auto record : aggregate_times) {
            outfile << record.first << " " << (record.second).c_cnt << " "
                    << (record.second).duration/*/1000000.0*/ << "ns, "
                    << (record.second).sync_duration/*/1000000.0*/ << "ns" << std::endl;
        }

        outfile.close();
    }
    
    void SignalStartInstra() {
        // std::cout << "Signal start of intrumentation" << std::endl;
        if (!exec_times)
            exec_times = std::unique_ptr<std::vector<ExecTimeSPtr > >(
                new std::vector<ExecTimeSPtr >);
        if (!unresolved)
            unresolved = std::unique_ptr<std::unordered_map<uint64_t,
                std::stack<ExecTimeSPtr > > >(
                    new std::unordered_map<uint64_t, std::stack<ExecTimeSPtr > >);
        if (atexit(SAVE_INSTR_TIMES) != 0)
            std::cerr << "Failed to register atexit function" << std::endl;
    }

    void START_TIMER_INSTR(uint64_t offset, const char *name) {
        if (stop_timing) return;
        // std::cout << "-------Start timer for " << name << std::endl;
        if (exec_times.get() == NULL)
            SignalStartInstra();

        ExecTimeSPtr time = ExecTimeSPtr(new ExecTime);
        time->id = offset;
        time->func_name = name;
        if (unresolved->find(offset) == unresolved->end()) {
            std::stack<ExecTimeSPtr > times_for_id;
            unresolved->insert({offset, times_for_id});
        }
        unresolved->at(offset).push(time);
        auto start = hrc::now();
        unresolved->at(offset).top()->start_time = start;
    }

    void STOP_TIMER_INSTR(uint64_t offset, uint64_t id) {
        // std::cout << "id: " << id << std::endl;
        if (stop_timing) return;
        auto stop = hrc::now();
        ExecTimeSPtr time = ExecTimeSPtr(unresolved->at(offset).top());
        time->end_time = stop;
        time->duration = std::chrono::duration<double, std::nano>(
            stop - time->start_time).count();

        for (auto sync_time : sync_times) {
            time->sync_duration += sync_time.duration;
        }
        // clear vector so next API call can record sync times
        sync_times.clear();

        exec_times->push_back(time);
        unresolved->at(offset).pop();
    }

    void START_SYNC_TIMER_INSTR(uint64_t offset) {
        // std::cout << "Start sync timer on th " << pthread_self() << std::endl;

        SyncTime sync_time;
        sync_time.id = offset;

        auto start = hrc::now();
        sync_time.start_time = start;
        sync_times.push_back(sync_time);        
        // std::cout << "start recorded" << std::endl;
    }

    void STOP_SYNC_TIMER_INSTR(uint64_t offset) {
        // std::cout << "Stop sync timer" << std::endl;
        auto stop = hrc::now();

        SyncTime& sync_time = sync_times[sync_times.size()-1];
        sync_time.end_time = stop;
        sync_time.duration = std::chrono::duration<double, std::nano>(
            stop - sync_time.start_time).count();

        // std::cout << "stop recorded" << std::endl;
    }
}
