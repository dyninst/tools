#include "DyninstProcess.h"
//extern BPatch bpatch;
DyninstProcess::DyninstProcess(boost::program_options::variables_map vm, bool debug) {
	_vm = vm;
	_launchString = _vm["prog"].as<std::vector<std::string> >();
	_ops.reset(new DynOpsClass());
	_debug = debug;
	_aspace = NULL;
	_MPIProc = false;
	_openInsertions = false;
	_insertedInit = false;
}
DyninstProcess::DyninstProcess(std::string fileName, bool debug) {
	_launchString.push_back(fileName);
	_ops.reset(new DynOpsClass());
	_debug = debug;
	_aspace = NULL;
	_MPIProc = false;
	_openInsertions = false;
	_insertedInit = false;	
}
void DyninstProcess::SetDynOps(std::shared_ptr<DynOpsClass> ops) {
	_ops = ops;
}

std::shared_ptr<DynOpsClass> DyninstProcess::ReturnDynOps() {
	return _ops;
}

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

BPatch_object * DyninstProcess::LoadLibrary(std::string library) {
	/**
	 * Loads a library into the process. First performs a check of alreadly loaded libraries
	 * If the library is already loaded, returns the loaded library. Otherwise, calls the appropriate
	 * dyninst load function. 
	 */
	if (library.find("libcuda.so") != std::string::npos)
		library = std::string("libcuda.so.1");
	std::string original = library;
	std::map<BPatch_object *, boost::filesystem::path> loadedLibraries;
	BPatch_process * appProc = dynamic_cast<BPatch_process*>(_aspace);	
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
			return i.first;
		}
	}

	std::cerr << "[DyninstProcess::LoadLibrary] Loading libray - " << original << std::endl;
	// Not already loaded, return a new loaded library.
	return appProc->loadLibrary(original.c_str());
}

void DyninstProcess::CloseInsertionSet() {
	if (_openInsertions) {
		_aspace->finalizeInsertionSet(false);
		_openInsertions = false;
	}
}

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
	if (_MPIProc) {
		appProc->continueExecution();
		//sleep(5);
		//appProc->continueExecution();
	}
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

bool DyninstProcess::IsMPIProgram() {
	/**
	 * Checks to see if the program we are launching is an MPI program. If so, return true. Otherwise return false.
	 */
	std::vector<std::string> progName = _launchString; //_vm["prog"].as<std::vector<std::string> >();
	if (progName[0].find("mpirun") != std::string::npos || progName[0].find("/ij") != std::string::npos) 
		return true;
	return false;	
}

BPatch_addressSpace * DyninstProcess::LaunchProcess() {
	/**
	 * LaunchProcess:
	 * 		Launches the process with the information in variables_map vm (in key "prog", where "prog" is a std::vector of strings).
	 *
	 * Special case:
	 * 		If MPI launched application, use LaunchMPIProcess. 
	 *		
	 */
	if (_aspace != NULL) {
		std::cerr << "[DyninstProcess::LaunchProcess]  Process has already been launched, returning address space" << std::endl;
		return _aspace;
	}

	BPatch_addressSpace * handle = NULL;

	/* Check for special MPI case */
	if (IsMPIProgram())
		return LaunchMPIProcess();

	std::vector<std::string> progName = _launchString; //_vm["prog"].as<std::vector<std::string> >();
	
	// Setup program arguements
	char ** argv = (char**)malloc(progName.size() * sizeof(char *)+1);
	for (int i = 0; i < progName.size(); i++) 
		argv[i] = strdup(progName[i].c_str());
	argv[progName.size()] = NULL;
	for (int i = 0; i < progName.size(); i++){
		std::cerr << "[DyninstProcess::LaunchProcess] Launch Arguments - " <<  std::string(argv[i]) << std::endl;
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


BPatch_addressSpace * DyninstProcess::LaunchMPIProcess() {
	/** 
	 * Launches an MPI Process. This is fundamentally different from launching 
	 * a normal process with dyninst since we need to attach to the process that is launched
	 * by mpi itself (not the parent). Because SpectrumMPI does some weird things, we wait 
	 * until it has set everything up before attaching to the child (the actual target process).
	 */
	_MPIProc = true;
	BPatch_addressSpace * handle = NULL;

	// What this process entails is attaching to the process instead of launching it.
	// This REQUIRES that you use some other method to stop the process at the start of main
	// Such as kill(getpid(), SIGSTOP);
	std::vector<std::string> progName = _launchString;//_vm["prog"].as<std::vector<std::string> >();
	char ** argv = (char**)malloc(progName.size() * sizeof(char *)+1);
	int appPosition = -1;
	for (int i = 0; i < progName.size(); i++) {
		argv[i] = strdup(progName[i].c_str());
		if (i > 1 && appPosition == -1) {
			if (CheckIfFileExists(progName[i])) {
				appPosition = i;
			}
		}

	}
	argv[progName.size()] = NULL;
//	assert(appPosition != -1);
	int pid = -1;
	// Launch the other procees
	pid_t child_pid = fork();
	if (child_pid == 0){
		// Child process
		for (int i = 0; i < 10; i++){
			int retM = execvp(*argv, argv);
			std::cerr << "Launch Failed, trying agian.... Error Status: " <<  strerror(errno) << std::endl;
			sleep(2);
		}
		std::cerr << "FAILED TO LAUNCH PROCESS!\n";
		assert(1==0);
	} else {
		sleep(5);
		pid = child_pid;
		// Find the PID of the launched process
/*		std::stringstream ss;
		boost::filesystem::path tmp(progName[appPosition]);
		std::string filename = tmp.filename().string();
		ss << "pidof " << filename << std::endl;
		std::cerr << "[ProcessController::LaunchMPIProcess] Waiting on process " << filename << " to start" << std::endl;
		for (int i = 0; i < 10; i++){
			char line[250];
			FILE * command = popen(ss.str().c_str(),"r");
			if(fgets(line,250,command) > 0) {
				pid = atoi(line);
			}
			pclose(command);
			if (pid != -1)
				break;
			sleep(2);
		}
		*/
		assert(pid != -1);
	}
	bpatch.setInstrStackFrames(true);
	bpatch.setTrampRecursive(false);
	bpatch.setLivenessAnalysis(false);	
	std::cerr << "[DyninstProcess::LaunchMPIProcess] Attaching to process " << argv[0] << " at pid " << pid << std::endl;
	handle = bpatch.processAttach((const char *)argv[0], pid);
	bpatch.setLivenessAnalysis(false);
	bpatch.setInstrStackFrames(true);
	bpatch.setTrampRecursive(false);
	assert(handle != NULL);	
	_aspace = handle;
	return handle;
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

BPatch_addressSpace * DyninstProcess::GetAddressSpace() {
	return _aspace;
}

