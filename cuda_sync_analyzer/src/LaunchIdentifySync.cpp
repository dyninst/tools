#include "LaunchIdentifySync.h"

LaunchIdentifySync::LaunchIdentifySync(std::shared_ptr<DyninstProcess> proc) : _proc(proc) { 

}

BPatch_point * LaunchIdentifySync::FindPreviousPoint(BPatch_point* point) {
	auto image = _proc->GetAddressSpace()->getImage();
	std::vector<BPatch_point *> points;
	image->findPoints((((uint64_t)point->getAddress()) - 0x4), points);
	if (points.size() > 0)
		return points[0];
	return point;
	//assert("SHOULD FIND A POINT BUT ARE NOT!!!" == 0);

}

void LaunchIdentifySync::InsertAnalysis(std::vector<uint64_t> functionsToTrace, std::string funcName, bool withExit, std::string helperLib) {
	std::shared_ptr<DynOpsClass> ops = _proc->ReturnDynOps();
	std::vector<BPatch_function *> main = ops->FindFuncsByName(_proc->GetAddressSpace(), std::string("main"), NULL);
	BPatch_object * libCuda = _proc->LoadLibrary(std::string("libcuda.so.1"));
	BPatch_object * driverAPIWrapper = _proc->LoadLibrary(std::string(LOCAL_INSTALL_PATH) + helperLib);
	
	std::vector<BPatch_function *> cEntry = ops->FindFuncsByName(_proc->GetAddressSpace(), std::string("CALL_ENTRY"), driverAPIWrapper);
	std::vector<BPatch_function *> cExit = ops->FindFuncsByName(_proc->GetAddressSpace(), std::string("CALL_EXIT"), driverAPIWrapper);
	std::vector<BPatch_function *> signalStart = ops->FindFuncsByName(_proc->GetAddressSpace(), std::string("SignalStartInstra"), driverAPIWrapper);

	assert(cEntry.size() == 1 && cExit.size() == 1 && signalStart.size() == 1 && main.size() > 0);

	std::unordered_map<uint64_t, BPatch_function *> funcMap;
	std::vector<BPatch_function *> funcs;
	_proc->GetAddressSpace()->getImage()->getProcedures(funcs);
	uint64_t curId = 5;

	//std::unordered_map<uint64_t, uint64_t> idToOffset;
	for (auto i : funcs) {
		if (i->getModule()->getObject() == libCuda)
			funcMap[((uint64_t)i->getBaseAddr()) - ((uint64_t)i->getModule()->getBaseAddr())] = i;
	}
	_proc->BeginInsertionSet();
	for (auto i : functionsToTrace) {
		if (funcMap.find(i) == funcMap.end() || i < 0x200000){
			std::cerr << "Could not find function at offset = " << std::hex << i << std::endl;
		} else {
			std::cerr << "Inserting Instrumentation into function at offset = " << std::hex << i << " with id = " << std::dec << curId<< std::endl;
			std::vector<BPatch_snippet*> recordArgs;
			recordArgs.push_back(new BPatch_constExpr(curId));
			BPatch_funcCallExpr entryExpr(*cEntry[0], recordArgs);
			BPatch_funcCallExpr exitExpr(*cExit[0], recordArgs);
			auto f = funcMap[i];
			std::vector<BPatch_point*> * entry = f->findPoint(BPatch_locEntry);
			std::vector<BPatch_point*> * exit = f->findPoint(BPatch_locExit);
			_proc->GetAddressSpace()->insertSnippet(entryExpr,*entry);
			if (withExit){
				std::vector<BPatch_point*> prev;
				prev.push_back(FindPreviousPoint((*exit)[0]));
				_proc->GetAddressSpace()->insertSnippet(exitExpr,prev);
			}
			idToOffset[curId] = i;
			curId++;
			funcMap.erase(i);
		}
	}
	BPatch_function * mainFunc = main[0];
	if (main.size() > 1) {
		for (auto i : main)
			if (i->getModule()->getObject()->pathName().find(".so") == std::string::npos)
				mainFunc = i;
	}

	std::vector<BPatch_point*> * funcCalls = mainFunc->findPoint(BPatch_locSubroutine);
	for (auto i : *funcCalls) {
		if (i->getCalledFunction()->getName().find(funcName) != std::string::npos) {
			std::vector<BPatch_point*> singlePoint;
			singlePoint.push_back(i);
			std::vector<BPatch_snippet*> recordArgs;
			BPatch_funcCallExpr entryExpr(*signalStart[0], recordArgs);
			_proc->GetAddressSpace()->insertSnippet(entryExpr,singlePoint, BPatch_callBefore);
		}
	}
}

uint64_t LaunchIdentifySync::PostProcessing(std::vector<uint64_t> & allFound) {
	FILE * fp = fopen("MS_outputids.bin", "rb");
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint64_t id = 0;
	uint64_t gCount = 0;
	uint64_t highestValue = 0;
	uint64_t highestAddress = 0;
	while (size > 0) {
		fread(&id, 1, sizeof(uint64_t), fp);
		fread(&gCount, 1, sizeof(uint64_t), fp);
		size -= sizeof(uint64_t) * 2;
		std::cerr << "Location = " << std::hex << idToOffset[id] << std::dec << " gCount = " << gCount << std::endl;
		if (gCount > highestValue) {
			highestValue = gCount;
			highestAddress = idToOffset[id];
		}
		allFound.push_back(idToOffset[id]);
	}
	fclose(fp);
	return highestAddress;
}
