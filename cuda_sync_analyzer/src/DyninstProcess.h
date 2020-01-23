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

using namespace Dyninst;
using namespace ParseAPI;
using namespace PatchAPI;
using namespace SymtabAPI;

class DyninstProcess: public DyninstMutatee {
public:
    DyninstProcess(std::string fileName);
	BPatch_addressSpace * LaunchProcess();
	bool RunUntilCompleation(std::string filename = std::string(""));
	void SetDynOps(std::shared_ptr<DynOpsClass> ops);
	void BeginInsertionSet() override;
	void DetachForDebug();
	void RunCudaInit();
	void SetTrampGuard();

	void CloseInsertionSet();
private:
	std::vector<std::string> _launchString;
	bool _insertedInit;
	bool _openInsertions;
};
