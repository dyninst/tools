#include <map> 
#include <unordered_set>
#include <memory>
#include <iostream>
volatile int FINDSYNCFUNC_exited = 0;
volatile int START_INSTRA = 0;
volatile uint64_t FINDSYNCFUNC_globalCount = 0;

struct MapStore{
	std::map<uint64_t, uint64_t> ids;
	std::unordered_set<uint64_t> exclude; 
	void Entry(uint64_t id) {
		FINDSYNCFUNC_globalCount++;
		if (exclude.find(id) != exclude.end())
			return;
		if (ids.find(id) == ids.end())
			ids[id] = FINDSYNCFUNC_globalCount;
		else 
			Exit(id);
	};

	void Exit(uint64_t id) {
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
		SetupMemoryStructure();
		START_INSTRA = 1;
	}
	void CALL_ENTRY(uint64_t id) {
		if (FINDSYNCFUNC_exited > 0 || START_INSTRA == 0)
			return;
		SetupMemoryStructure();
		if (FINDSYNCFUNC_globalCount > 30000) {
			FINDSYNCFUNC_exited = 1;
			MS->WriteOutput();
			std::cerr << "Program Terminating" << std::endl;
			exit(0);
		}
		
		MS->Entry(id);
	};

	void CALL_EXIT(uint64_t id) {
		if (FINDSYNCFUNC_exited > 0 || START_INSTRA == 0)
			return;
		SetupMemoryStructure();
		MS->Exit(id);		
	};
}