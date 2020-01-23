#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <boost/filesystem.hpp>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_object.h"

#include "DynOpsClass.h"

using namespace Dyninst;

class DyninstMutatee {
public:
    BPatch_addressSpace * GetAddressSpace();
    std::shared_ptr<DynOpsClass> ReturnDynOps();
    virtual void BeginInsertionSet();
    BPatch_object * LoadLibrary(std::string library);
protected:
    std::shared_ptr<DynOpsClass> _ops;
    BPatch_addressSpace * _aspace;
    BPatch bpatch;
};
