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
};

typedef std::shared_ptr<ExecTime> ExecTimeSPtr;

std::unique_ptr<std::vector<ExecTimeSPtr > > exec_times;
std::unique_ptr<std::unordered_map<uint64_t, std::stack<ExecTimeSPtr > > > unresolved;

extern "C" {
    void SAVE_INSTR_TIMES() {
        std::ofstream outfile("InstrTimings.out");
        assert(outfile.good());
        std::unordered_map<std::string, uint64_t> aggregate_times;

        //outfile << "Function\t\tTime (ns)" << std::endl;
        for (std::vector<ExecTimeSPtr >::iterator it = exec_times->begin(); it != exec_times->end(); ++it) {
            auto record = it->get();
            // outfile << record->func_name << " " << std::hex << record->id << " "
            //     << std::dec << record->duration << " ns" << std::endl;
            if (aggregate_times.find(record->func_name) == aggregate_times.end()) {
                aggregate_times[record->func_name] = 0;
            }
            aggregate_times[record->func_name] += record->duration;
        }

        for (std::pair<std::string, uint64_t> record : aggregate_times) {
            outfile << record.first << " " << record.second << " ns" << std::endl;
        }

        outfile.close();
    }
    
    void SignalStartInstra() {
        //std::cout << "Signal start of intrumentation" << std::endl;
        if (!exec_times)
            exec_times = std::unique_ptr<std::vector<ExecTimeSPtr > >(new std::vector<ExecTimeSPtr >);
        if (!unresolved)
            unresolved = std::unique_ptr<std::unordered_map<uint64_t, std::stack<ExecTimeSPtr > > >(
                    new std::unordered_map<uint64_t, std::stack<ExecTimeSPtr > >);
        if (atexit(SAVE_INSTR_TIMES) != 0)
            std::cerr << "Failed to register atexit function" << std::endl;
    }
    void START_TIMER_INSTR(uint64_t offset, const char *name) {
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
    void STOP_TIMER_INSTR(uint64_t offset) {
        auto stop = hrc::now();
        ExecTimeSPtr time = ExecTimeSPtr(unresolved->at(offset).top());
        time->end_time = stop;
        time->duration = std::chrono::duration<double, std::nano>(
            stop - time->start_time).count();
        exec_times->push_back(time);
        unresolved->at(offset).pop();
    }
}
