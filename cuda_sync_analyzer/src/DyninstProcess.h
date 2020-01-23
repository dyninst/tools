#pragma once
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
#include "DyninstMutatee.h"

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
//#include "StackPoint.h"
//#include "StackStorage.h"

using namespace Dyninst;
using namespace ParseAPI;
using namespace PatchAPI;
using namespace SymtabAPI;

class DyninstProcess: public DyninstMutatee {
public:
    DyninstProcess(std::string fileName);
    //BPatch_addressSpace * OpenBinary();
	BPatch_addressSpace * LaunchProcess();
	//BPatch_addressSpace * GetAddressSpace() override;
	bool RunUntilCompleation(std::string filename = std::string(""));
    //bool WriteFile(std::string newName);
	//BPatch_object * LoadLibrary(std::string library);
	void SetDynOps(std::shared_ptr<DynOpsClass> ops);
	//std::shared_ptr<DynOpsClass> ReturnDynOps() override;
	void BeginInsertionSet() override;
	void DetachForDebug();
	void RunCudaInit(std::string libcudaName = "libcuda.so.1");
	void SetTrampGuard();

	void CloseInsertionSet();
private:
	std::vector<std::string> _launchString;
	//std::shared_ptr<DynOpsClass> _ops;
	bool _insertedInit;
	//BPatch_addressSpace * _aspace;
	bool _openInsertions;
	//BPatch bpatch;
};
