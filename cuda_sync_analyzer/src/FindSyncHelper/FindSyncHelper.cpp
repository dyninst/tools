#include <iostream>
#include <map> 
#include <memory>
//#include <mutex>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>

// See man 2 gettid
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)

volatile int FINDSYNCFUNC_exited = 0;
volatile int START_INSTRA = 0;
volatile uint64_t FINDSYNCFUNC_globalCount = 0;
volatile pid_t MAIN_tid = 0;

struct MapStore{
	std::map<uint64_t, uint64_t> ids;
	std::unordered_set<uint64_t> exclude;
    //std::mutex m;

	void Entry(uint64_t id) {
//        std::scoped_lock(m);
		FINDSYNCFUNC_globalCount++;
		if (exclude.find(id) != exclude.end())
			return;
		if (ids.find(id) == ids.end())
			ids[id] = FINDSYNCFUNC_globalCount;
//		else
//			Exit(id);
	};

	void Exit(uint64_t id) {
//        std::scoped_lock(m);
		if (ids.find(id) != ids.end())
			ids.erase(id);
		exclude.insert(id);
	};

	void WriteOutput() {
		FILE * f = fopen("MS_outputids.bin", "wb");
		uint64_t id = 0;
		uint64_t gcount = 0;
		for (auto i : ids) {
			id = i.first;
			gcount = i.second;
			fwrite(&id, 1, sizeof(uint64_t),f);
			fwrite(&gcount, 1, sizeof(uint64_t),f);
			std::cerr << "Wrote id = " << id << " count = " << gcount << std::endl;
		}
		fclose(f);
	};

	~MapStore() {
		FINDSYNCFUNC_exited = 1;
		START_INSTRA = 0;
	};
};

std::shared_ptr<MapStore> MS;

extern "C" {
	void SetupMemoryStructure() {
		if (MS.get() == NULL && FINDSYNCFUNC_exited == 0){
			MS = std::shared_ptr<MapStore>(new MapStore());
		}
	}

	void SignalStartInstra() {
        MAIN_tid = gettid();
		SetupMemoryStructure();
		START_INSTRA = 1;
	}
	void CALL_ENTRY(uint64_t id) {
        if (gettid() != MAIN_tid) return;
		if (FINDSYNCFUNC_exited > 0 || START_INSTRA == 0)
			return;
		SetupMemoryStructure();
		if (FINDSYNCFUNC_globalCount > 300000) {
			FINDSYNCFUNC_exited = 1;
			MS->WriteOutput();
			std::cerr << "Program Terminating" << std::endl;
			exit(0);
		}
		
		MS->Entry(id);
	};

	void CALL_EXIT(uint64_t id) {
        if (gettid() != MAIN_tid) return;
		if (FINDSYNCFUNC_exited > 0 || START_INSTRA == 0)
			return;
		SetupMemoryStructure();
		MS->Exit(id);		
	};
}
