#pragma once
#include <string.h>
#include <algorithm>
#include <functional>
#include <array>
#include <iostream>
#include <cassert>
#include <deque>
#include <sys/time.h>
#include <cstdlib>
#include <sstream>
#include <tuple>
#include <utility> 
#include <stdarg.h>
#include <map>
#include <set> 
#include <iomanip>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <mutex>
#include <queue>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

// Dyninst includes
#include "CodeObject.h"
#include "CFG.h"
#include "PatchObject.h"
#include "PatchMgr.h"
#include "Point.h"
#include "BPatch_object.h"
#include "BPatch_snippet.h"
#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_image.h"
#include "BPatch_function.h"
#include "BPatch_Vector.h"
#include "BPatch_point.h"
#include "BPatch_addressSpace.h"
#include "BPatch_statement.h"
#include "BPatch_basicBlock.h"
#include "BPatch_flowGraph.h"
#include "dynC.h"
#include "set"
#include "LogInfo.h"
#include "Constants.h"
#include "StackPoint.h"
#include "StackStorage.h"
#include "LocateCudaSynchronization.h"
#include "SymbolLookup.h"
using namespace Dyninst;
using namespace ParseAPI;
using namespace PatchAPI;
using namespace SymtabAPI;

typedef std::shared_ptr<std::vector<BPatch_point *>> BPatchPointVecPtr;
// Perform common operations on dyninst objects
class DynOpsClass {
public:
	DynOpsClass();
	int FindFuncByStackPoint(BPatch_addressSpace * aspace, BPatch_function * & ret, StackPoint & point);
	int FindFuncByName(BPatch_addressSpace * aspace, BPatch_function * & ret, std::string name);
	int FindFuncByLibnameOffset(BPatch_addressSpace * aspace, BPatch_function * & ret, std::string libname, uint64_t offset, bool exact = true);
	BPatch_object * FindObjectByName(BPatch_addressSpace * aspace, std::string & name, bool exact = true);
	bool GetFileOffset(BPatch_addressSpace * aspace, BPatch_point * point, uint64_t & addr, bool addInstSize = false);
	Dyninst::InstructionAPI::Instruction FindInstructionAtPoint(BPatch_point * point);
	void SetupPowerMap(BPatch_addressSpace * addr);
	std::vector<BPatch_object *> GetObjects(BPatch_addressSpace * aspace);
	BPatch_function * GetPOWERFunction(BPatch_function * function);
	std::vector<BPatch_function*> FindFunctionsByLibnameOffset(BPatch_addressSpace * aspace, std::string libname, uint64_t offset, bool exact);
	void GetBasicBlocks(BPatch_function * func, std::set<BPatch_basicBlock *> & ret);
	// New replacement functions
	void PowerFunctionCheck(BPatch_addressSpace * addr, BPatch_function * & funcToCheck);
	std::vector<BPatch_function *> FindFuncsInObjectByName(BPatch_addressSpace * aspace, BPatch_object * obj, std::string name);
	std::vector<BPatch_function *> FindFuncsByName(BPatch_addressSpace * aspace, std::string name, BPatch_object * obj = NULL);
	std::vector<BPatch_function *> GetFunctionsByOffeset(BPatch_addressSpace * aspace, BPatch_object * obj, uint64_t offset);
	uint64_t GetSyncFunctionLocation();
	bool FillStackpoint(BPatch_addressSpace * aspace, StackPoint & p);
	BPatchPointVecPtr GetPoints(BPatch_function * func, const BPatch_procedureLocation pos);
	bool IsNeverInstriment(BPatch_function * func);
	StackPoint GenerateStackPoint(BPatch_addressSpace * aspace, BPatch_function * func);

	BPatch_function * FindFunctionInAddrList(BPatch_addressSpace * aspace, StackPoint & p);
	void GenerateAddrList(BPatch_addressSpace * aspace);

	std::map<uint64_t, std::string> GetRealAddressAndLibName(BPatch_addressSpace * aspace);
private:
	std::map<uint64_t, BPatch_function *> _powerFuncmap;
	std::unordered_map<uint64_t, BPatch_function *> _addressList;
	bool init;
	uint64_t _syncLocation;
	LocateCudaSynchronization _syncClass;
};
