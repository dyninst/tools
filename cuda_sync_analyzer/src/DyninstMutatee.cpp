#include "DyninstMutatee.h"

BPatch_object * DyninstMutatee::LoadLibrary(std::string library) {
    /**
     * Loads a library into the process. First performs a check of alreadly loaded libraries
     * If the library is already loaded, returns the loaded library. Otherwise, calls the appropriate
     * dyninst load function.
     */
    //if (library.find("libcuda.so") != std::string::npos)
    //  library = std::string("libcuda.so.1");
    std::string original = library;
    std::map<BPatch_object *, boost::filesystem::path> loadedLibraries;
    //BPatch_process * appProc = dynamic_cast<BPatch_process*>(_aspace);
    std::vector<BPatch_object *> objects = _ops->GetObjects(_aspace);
    for (auto i : objects) {
        boost::filesystem::path tmp(i->pathName());
        loadedLibraries[i] = tmp;
    }

    // Dump everything after ".so" in the binary name.
    if (library.find(".so") != std::string::npos)
        library = library.substr(0, library.find(".so") + 3);

    std::transform(library.begin(), library.end(), library.begin(), ::tolower);

    for (auto i : loadedLibraries) {
        std::string filename = i.second.filename().string();
        if (filename.find(".so") != std::string::npos)
            filename = filename.substr(0, filename.find(".so") + 3);
        std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
        if (filename == library) {
            std::cout << "[DyninstProcess::LoadLibrary] Library already loaded."
                << " Not loading again: " << filename << std::endl;
            return i.first;
        }
    }

    std::cerr << "[DyninstProcess::LoadLibrary] Loading library - " << original << std::endl;
    // Not already loaded, return a new loaded library.
    return _aspace->loadLibrary(original.c_str());
}

void DyninstMutatee::BeginInsertionSet() {
    if (_openInsertions)
        return;
    _aspace->beginInsertionSet();
    _openInsertions = true;
}

void DyninstMutatee::CloseInsertionSet() {
    if (_openInsertions) {
        // set to true because of the issue where sync time is not computed
        _aspace->finalizeInsertionSet(true);
        _openInsertions = false;
    }
}

std::shared_ptr<DynOpsClass> DyninstMutatee::ReturnDynOps() {
    return _ops;
}

BPatch_addressSpace * DyninstMutatee::GetAddressSpace() {
    return _aspace;
}
