#pragma once
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <string>
#include <vector>
#include <map>
#include <cassert>
#include <iostream>
#include <memory>
#include <algorithm>
#include <sys/types.h>
#include <unistd.h>

#include "DynOpsClass.h"
#include "Common.h"

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
#include "dynC.h"
#include "set"
#include "LogInfo.h"
#include "Constants.h"
#include "StackPoint.h"
#include "StackStorage.h"

using namespace Dyninst;
using namespace ParseAPI;
using namespace PatchAPI;
using namespace SymtabAPI;

class DyninstProcess {
public:
	DyninstProcess(boost::program_options::variables_map vm, bool debug);
	DyninstProcess(std::string fileName, bool debug);
	BPatch_addressSpace * LaunchProcess();
	BPatch_addressSpace * GetAddressSpace();
	bool RunUntilCompleation(std::string filename = std::string(""));
	BPatch_object * LoadLibrary(std::string library);
	void SetDynOps(std::shared_ptr<DynOpsClass> ops);
	std::shared_ptr<DynOpsClass> ReturnDynOps();
	void BeginInsertionSet();
	void DetachForDebug();
	void RunCudaInit();
	void SetTrampGuard();

	void CloseInsertionSet();
private:
	bool IsMPIProgram();
	BPatch_addressSpace * LaunchMPIProcess();
	std::vector<std::string> _launchString;
	std::shared_ptr<DynOpsClass> _ops;
	bool _debug;
	bool _MPIProc;
	bool _insertedInit;
	BPatch_addressSpace * _aspace;
	boost::program_options::variables_map _vm;
	bool _openInsertions;
	BPatch bpatch;
};
