#include "BPatchBinary.h"

BPatchBinary::BPatchBinary(std::string binName, bool output, std::string outName)  :
	_binName(binName), _output(output), _outName(outName) {
	_as = bpatch.openBinary(_binName.c_str(), false);
	assert(_as != NULL);
	_be = dynamic_cast<BPatch_binaryEdit*>(_as);
}

BPatchBinary::~BPatchBinary() {
	if(_output)
		if(!_be->writeFile(_outName.c_str()))
			std::cerr << "Could not generate output binary - " << _outName << std::endl;
}

std::vector<uint64_t> BPatchBinary::FindSyncCandidates() {
	std::unordered_map<std::string, BPatch_function *> func_map;
	std::vector<BPatch_function *> all_functions;
	
	BPatch_image * _img = _be->getImage();
	_img->getProcedures(all_functions);
	for (auto i : all_functions) {
		if (func_map.find(i->getName()) == func_map.end()){
			func_map[i->getName()] = i;
		} else {
			uint64_t address = (uint64_t)i->getBaseAddr();	
			uint64_t origAddress = (uint64_t)func_map[i->getName()]->getBaseAddr();	
			// Grab the power function without preamble
			if (address > origAddress) 
				func_map[i->getName()] = i;
		}
	}

	std::vector<std::string> functionsToParse = {"cuCtxSynchronize","cuStreamSynchronize","cuMemcpyDtoH_v2","cuMemcpyDtoHAsync_v2","cuMemFree_v2"};
	std::vector<std::shared_ptr<FuncCFG>> funcCFGs;
	std::unordered_map<BPatch_function *, std::shared_ptr<FuncCFG>> functionToFuncCFG;
	//std::vector<std::unordered_map<std::shared_ptr<FuncCFG>, int>> levelOrderDump;
	std::unordered_set<BPatch_function *> seen;
	int posSeen = 0;
	for (auto i : functionsToParse) {
		seen.clear();
		if (func_map.find(i) == func_map.end()) {
			std::cerr << "Could not find function - " << i << std::endl;
			continue;
		}

		std::deque<BPatch_function *> queue;
		queue.push_back(func_map[i]);
		seen.insert(func_map[i]);
		bool first = false;
		while(queue.size() > 0) {
			auto curFunc = queue.front();
			queue.pop_front();
			std::shared_ptr<FuncCFG> current;
			if (functionToFuncCFG.find(curFunc) == functionToFuncCFG.end()) {
				current = std::shared_ptr<FuncCFG>(new FuncCFG(curFunc, functionsToParse.size()));
				functionToFuncCFG[curFunc] = current;
			}
			else 
				current = functionToFuncCFG[curFunc];
			if (first == false) {
				funcCFGs.push_back(current);
				first = true;
			}
			current->SetSeen(posSeen);
			std::shared_ptr<std::vector<BPatch_point *>> funcCalls(curFunc->findPoint(BPatch_locSubroutine));
			for (auto f : *funcCalls) {
				BPatch_function * calledFunction = f->getCalledFunction();
				if (calledFunction == NULL)
					continue;
				if (functionToFuncCFG.find(calledFunction) == functionToFuncCFG.end()) {
					functionToFuncCFG[calledFunction] = std::shared_ptr<FuncCFG>(new FuncCFG(calledFunction, functionsToParse.size()));
				}
				current->InsertChild(functionToFuncCFG[calledFunction]);
				functionToFuncCFG[calledFunction]->InsertParent(current);
				functionToFuncCFG[calledFunction]->SetSeen(posSeen);
				if (seen.find(calledFunction) == seen.end()) {
					queue.push_back(calledFunction);
					seen.insert(calledFunction);
				}
			}
		}
		posSeen++;
	}
	for (auto i : funcCFGs) {
		std::unordered_set<std::shared_ptr<FuncCFG>> tmp_set;
		tmp_set.insert(i);
		std::string diaGraph = i->GetDotString(tmp_set);
		diaGraph = "graph " + i->getName() + "_graph {\n" + diaGraph + "\n}";
		std::ofstream diaFile(i->getName() + ".dot",  std::ofstream::out);
		diaFile << diaGraph << std::endl;
		diaFile.close();
		for (auto n : tmp_set) {
			n->_inTraversal = false;
		}
	}
	std::vector<uint64_t> ret;
	//std::vector<std::unordered_map<std::shared_ptr<FuncCFG>, int>> levelOrderDump;
	std::unordered_map<std::shared_ptr<FuncCFG>, int> mapInterSect;
	for (auto i : functionToFuncCFG) {
		if (i.second->HasAllSeen()){
			ret.push_back((uint64_t)i.first->getBaseAddr());
		}
	}
/*
	for (auto i : funcCFGs) {
		std::cout << i->getName() << std::endl;
		std::deque<std::shared_ptr<FuncCFG>> queue;
		levelOrderDump.push_back(std::unordered_map<std::shared_ptr<FuncCFG>, int>());
		queue.push_back(i);
		int level = 0;
		while (queue.size() > 0) {
			auto curFunc = queue.front();
			queue.pop_front();
			if (levelOrderDump.back().find(curFunc) == levelOrderDump.back().end()) {
				levelOrderDump.back()[curFunc] = level;
			} else {
				continue;
			}
			level++;
			for (auto n : curFunc->children) {
				queue.push_back(n);
			}
		}
	}
	assert(levelOrderDump.size() > 0);
	std::unordered_map<std::shared_ptr<FuncCFG>, int> mapInterSect(levelOrderDump[0]);
	for(int i = 1; i < levelOrderDump.size(); i++) {
		std::unordered_map<std::shared_ptr<FuncCFG>, int> intertmp;
		for (auto n : levelOrderDump[i]) {
			if (mapInterSect.find(n.first) != mapInterSect.end()) {
				intertmp[n.first] = std::max(n.second, mapInterSect[n.first]);
			}
		}
		mapInterSect = intertmp;
	}
*/
	// for(auto i : mapInterSect) {
	// 	std::cout << i.second << "," << i.first->getName() << "," << std::hex << i.first->getAddress() << std::endl;
	// }
	return ret;
/*
	std::vector<std::unordered_set<std::shared_ptr<FuncCFG>>> currentLevel;
	std::vector<std::unordered_set<std::shared_ptr<FuncCFG>>> levelOrderIntersect;
	for (auto i : funcCFGs) {
		std::unordered_set<std::shared_ptr<FuncCFG>> tmp;
		tmp.insert(i);
		currentLevel.push_back(tmp);
	}

	// level order traversal
	if (currentLevel.size() == 0) {
		std::cerr << "Not matching anything!" << std::endl;
		return std::vector<uint64_t>();
	}
	for (int i = 0; i < 10; i++) {
		std::unordered_set<std::shared_ptr<FuncCFG>> matchSet = currentLevel[0];
		levelOrderIntersect.push_back(std::unordered_set<std::shared_ptr<FuncCFG>>());
		for (auto n : currentLevel) {
			if (matchSet.find(n) != matchSet.end()) {

			}
		}

	}
*/
}


BPatch_image * BPatchBinary::GetImage() {
	return _be->getImage();
}

BPatch_addressSpace * BPatchBinary::GetAddressSpace() {
	return _as;
}