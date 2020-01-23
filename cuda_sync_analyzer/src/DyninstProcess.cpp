#include "DyninstProcess.h"

DyninstProcess::DyninstProcess(std::string fileName) {
	_launchString.push_back(fileName);
	_ops.reset(new DynOpsClass());
	_aspace = NULL;
	_openInsertions = false;
	_insertedInit = false;	
}
void DyninstProcess::SetDynOps(std::shared_ptr<DynOpsClass> ops) {
	_ops = ops;
}
/*
std::shared_ptr<DynOpsClass> DyninstProcess::ReturnDynOps() {
	return _ops;
}
*/
void DyninstProcess::RunCudaInit() {
	if (_insertedInit)
		return;

	BPatch_object * libcuda = LoadLibrary(std::string("libcuda.so.1"));
	std::vector<BPatch_function *> cuInit = _ops->FindFuncsByName(_aspace, std::string("cuInit"), libcuda);
	assert(cuInit.size() == 1);
	std::vector<BPatch_snippet*> recordArgs;
	recordArgs.push_back(new BPatch_constExpr(uint64_t(0)));
	BPatch_funcCallExpr entryExpr(*(cuInit[0]), recordArgs);
	std::cerr << "[DyninstProcess::RunCudaInit] Fireing off one time call to call cuInit\n";
	dynamic_cast<BPatch_process*>(_aspace)->oneTimeCode(entryExpr);
	_insertedInit = true;
}

void DyninstProcess::BeginInsertionSet() {
	if (_openInsertions)
		return;
	_aspace->beginInsertionSet();
	_openInsertions = true;
}
/*
BPatch_object * DyninstProcess::LoadLibrary(std::string library) {
	/**
	 * Loads a library into the process. First performs a check of alreadly loaded libraries
	 * If the library is already loaded, returns the loaded library. Otherwise, calls the appropriate
	 * dyninst load function. 
	 */
/*
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
*/
void DyninstProcess::CloseInsertionSet() {
	if (_openInsertions) {
		_aspace->finalizeInsertionSet(false);
		_openInsertions = false;
	}
}
/*
bool DyninstProcess::WriteFile(std::string newName) {
    assert(!newName.empty());
    BPatch_binaryEdit* appBin = dynamic_cast<BPatch_binaryEdit*>(_aspace);
    if (appBin) {
        if (!appBin->writeFile(newName.c_str())) {
            std::cerr << "writeFile failed for binary " << newName << std::endl;
            return false;
        }   
        return true;
    }
    std::cerr << "Not a BPatch_binaryEdit object" << std::endl;
    return false;
}
*/
bool DyninstProcess::RunUntilCompleation(std::string filename) {
	int terminal_stdout, terminal_stderr;
	/**
	 * Run the process until it finishes.
	 */
	if (_openInsertions)
		_aspace->finalizeInsertionSet(false);

	BPatch_process * appProc = dynamic_cast<BPatch_process*>(_aspace);

	// if (filename != std::string("")){
	// 	// Capture applicaiton stdout/stderr
	// 	terminal_stdout = dup(fileno(stdout));
	// 	terminal_stderr = dup(fileno(stderr));
	// 	remove(filename.c_str());
	// 	freopen(filename.c_str(),"w",stdout);
	// 	dup2(fileno(stdout), fileno(stderr));		
	// }

	//std::vector<std::string> progName = _vm["prog"].as<std::vector<std::string> >();
	assert(appProc->continueExecution() == true);
	// while(appProc->isStopped() == true && appProc->terminationStatus() == NoExit){
	// 	appProc->continueExecution();
	// }
	while(!appProc->isTerminated()) {
		//std::cerr << "Iteration of Termination loop" << std::endl;
		bpatch.pollForStatusChange();
		//bpatch.waitForStatusChange();
		sleep(2);
		if (appProc->isStopped()){
			if(appProc->isTerminated())
				break;

			assert(appProc->continueExecution() == true);
		}
	}


	// Return stderr/out to terminal.
	// if (filename != std::string("")){
	// 	dup2(terminal_stdout, fileno(stdout));
	// 	dup2(terminal_stderr, fileno(stderr));
	// 	close(terminal_stderr);
	// 	close(terminal_stdout);			
	// }
	return true;
}
/*
BPatch_addressSpace * DyninstProcess::OpenBinary() {
    BPatch_addressSpace * handle = bpatch.openBinary(_launchString[0].c_str(), true);
    if (!handle)
        std::cerr << "openBinary failed" << std::endl;
    _aspace = handle;
    return handle;
}
*/
BPatch_addressSpace * DyninstProcess::LaunchProcess() {
	/**
	 * LaunchProcess:
	 * 		Launches the process from _launchString (std::vector of prog name and arguments).
	 *
	 */
	if (_aspace != NULL) {
		std::cerr << "[DyninstProcess::LaunchProcess] "
            << "Process has already been launched, returning address space" << std::endl;
		return _aspace;
	}

	BPatch_addressSpace * handle = NULL;

	std::vector<std::string> progName = _launchString;
	
	// Setup program arguements
	char ** argv = (char**)malloc(progName.size() * sizeof(char *)+1);
	for (int i = 0; i < progName.size(); i++) 
		argv[i] = strdup(progName[i].c_str());
	argv[progName.size()] = NULL;
	for (int i = 0; i < progName.size(); i++){
		std::cerr << "[DyninstProcess::LaunchProcess] Launch Arguments - "
            << std::string(argv[i]) << std::endl;
	}

	bpatch.setInstrStackFrames(true);
	bpatch.setTrampRecursive(false);
	bpatch.setLivenessAnalysis(false);
	handle = bpatch.processCreate(argv[0],(const char **)argv);
	bpatch.setLivenessAnalysis(false);
	bpatch.setInstrStackFrames(true);
	bpatch.setTrampRecursive(false);
	assert(handle != NULL);	
	
	_aspace = handle;
	return _aspace;
}

void DyninstProcess::SetTrampGuard() {
	bpatch.setTrampRecursive(true);
}


void DyninstProcess::DetachForDebug() {
	std::cerr << "FOR DEBUG PURPOSES ONLY!!!!!!" << std::endl;
	std::cerr << "We will now detach from the process and spin forever.... " << std::endl;
	if (_openInsertions)
		_aspace->finalizeInsertionSet(false);
	BPatch_process * appProc = dynamic_cast<BPatch_process*>(_aspace);
	appProc->detach(false);

	while(1) {
		sleep(10);
	}


}
