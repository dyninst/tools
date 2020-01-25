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
    hrc::time_point start_time;
    hrc::time_point end_time;
};

typedef std::shared_ptr<ExecTime> ExecTimeSPtr;

std::unique_ptr<std::vector<ExecTimeSPtr > > exec_times;
std::unique_ptr<std::unordered_map<uint64_t, std::stack<ExecTimeSPtr > > > unresolved;

extern "C" {
    void SAVE_INSTR_TIMES() {
        std::ofstream outfile("InstrTimings.out");
        assert(outfile.good());
        for (std::vector<ExecTimeSPtr >::iterator it = exec_times->begin(); it != exec_times->end(); ++it)
            outfile << std::hex << it->get()->id << " " << std::dec
                << std::chrono::duration<double, std::nano>(it->get()->end_time - it->get()->start_time).count()
                << " ns" << std::endl;
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
    void START_TIMER_INSTR(uint64_t offset) {
        if (exec_times.get() == NULL)
            SignalStartInstra();
        ExecTimeSPtr time = ExecTimeSPtr(new ExecTime);
        time->id = offset;
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
        unresolved->at(offset).pop();
        exec_times->push_back(time);
    }
}
