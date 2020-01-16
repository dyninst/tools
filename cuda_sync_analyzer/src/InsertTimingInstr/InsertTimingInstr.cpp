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

// Struct { start, end, id };

// vector<Structs> times;

// vector<Structs> unresoived;
// map<id, vector<struct> > unresolved;
// unordered_map<id, vector<struct>> unresolved;

// Entry() { unresolved.push_back(start, 0, id) };

// Exit() { for(int i = unresolved.size() - 1; ....; i--){if(unresolved[i].id == id) add end time, close)}


struct ExecTime {
    uint64_t id;
    hrc::time_point start_time;
    hrc::time_point end_time;
};


std::unique_ptr<std::vector<std::shared_ptr<ExecTime> > > exec_times;
std::unique_ptr<std::unordered_map<uint64_t, std::stack<std::shared_ptr<ExecTime> > > > unresolved;

extern "C" {
    void SAVE_INSTR_TIMES() {
        std::ofstream outfile("InstrTimings.out");
        assert(outfile.good());
        for (std::vector<std::shared_ptr<ExecTime> >::iterator it = exec_times->begin(); it != exec_times->end(); ++it)
            outfile << std::hex << it->get()->id << " " << std::dec
                << std::chrono::duration<double, std::nano>(it->get()->end_time - it->get()->start_time).count()
                << " ns" << std::endl;
        outfile.close();
/*
        FILE * f = fopen("MS_outputtimes.bin", "wb");
        for (std::vector<ExecTime>::iterator it = times->begin(); it != times->end(); ++it) {
            fwrite(&(it->id), 1, sizeof(uint64_t),f);
            uint64_t wtime = std::chrono::duration<double, std::nano>(it->end_time - it->start_time).count();
            fwrite(&wtime, 1, sizeof(uint64_t),f);
        }
        fclose(f);
*/    }
    
    void SignalStartInstra() {
        //std::cout << "Signal start of intrumentation" << std::endl;
        if (!exec_times)
            exec_times = std::unique_ptr<std::vector<std::shared_ptr<ExecTime> > >(new std::vector<std::shared_ptr<ExecTime> >);
        if (!unresolved)
            unresolved = std::unique_ptr<std::unordered_map<uint64_t, std::stack<std::shared_ptr<ExecTime> > > >(
                    new std::unordered_map<uint64_t, std::stack<std::shared_ptr<ExecTime> > >);
        if (atexit(SAVE_INSTR_TIMES) != 0)
            std::cerr << "Failed to register atexit function" << std::endl;
    }
    void START_TIMER_INSTR(uint64_t offset) {
        if (exec_times.get() == NULL)
            SignalStartInstra();
        std::shared_ptr<ExecTime> time = std::shared_ptr<ExecTime>(new ExecTime);
        time->id = offset;
        if (unresolved->find(offset) == unresolved->end()) {
            //std::shared_ptr<std::stack<ExecTime> > times_for_id = std::unique_ptr<std::stack<ExecTime> >(new std::stack<ExecTime>);
            std::stack<std::shared_ptr<ExecTime> > times_for_id;
            unresolved->insert({offset, times_for_id});
        }
        unresolved->at(offset).push(time);
        auto start = hrc::now();
        unresolved->at(offset).top()->start_time = start;
    }
    void STOP_TIMER_INSTR(uint64_t offset) {
        auto stop = hrc::now();
        std::shared_ptr<ExecTime> time = std::shared_ptr<ExecTime>(unresolved->at(offset).top());
        time->end_time = stop;
        unresolved->at(offset).pop();
        exec_times->push_back(time);
    }
}
