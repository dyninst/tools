/******
 * LocateCudaSynchronization
 * 
 * The purpose of this class is to return the offset to the internal synchronization 
 *     within libcuda.so. Right now this class looks these values up in a file that
 *	   contains the following information:
 *     <MD5 HASH of LIBCUDA>$<SYNCOFFSET>
 */
#include "LocateCudaSynchronization.h"
#define DEBUG_LOCATECUDA 1
uint64_t LocateCudaSynchronization::FindLibcudaOffset(bool dassert) {
	std::string md5cuda = GetMD5Sum(FindLibCuda());
	assert(md5cuda != std::string(""));
	std::map<std::string, uint64_t> driverList = ReadDriverList();
	if (driverList.find(md5cuda) == driverList.end()) {
		std::cerr << "[LocateCudaSynchronization::FindLibcudaOffset] Could not find a match for machine driver " 
				  << FindLibCuda() << " with an md5sum of " << md5cuda << std::endl;
		std::cerr << "Dumping Supported Driver MD5SUMs with Offsets: " << std::endl;
		for (auto i : driverList) 
			std::cerr << i.first << "," << std::hex << i.second << std::endl;
		if(dassert == true)
			assert(driverList.find(md5cuda) != driverList.end());
		return 0;
	}
	return driverList[md5cuda];
}

std::map<std::string, uint64_t> LocateCudaSynchronization::ReadDriverList() {
	/** 
	 * Reads the driver list file installed in std::string(LOCAL_INSTALL_PATH) + std::string("/lib/SyncDriverVerisons.txt")
	 */
	std::map<std::string, uint64_t>  ret;
	std::ifstream t(std::string(LOCAL_INSTALL_PATH) + std::string("/lib/SyncDriverVerisons.txt"), std::ios::binary);
	if (!t.good()){
		std::cerr << "[LocateCudaSynchronization::ReadDriverList] Could not open driver list file at " 
				  << std::string(LOCAL_INSTALL_PATH) + std::string("/lib/SyncDriverVerisons.txt") << std::endl;
		assert(t.good() == true);
	}
	std::string line;
	while (std::getline(t, line)) {
		// erase the newline if it appears in the line
		if (line.find('\n') != std::string::npos)
			line.erase(line.find('\n'), 1);
		std::vector<std::string> res;
		StringSplit(line, '$', res);
		if (res.size() != 2)
			continue;
		std::transform(res[0].begin(), res[0].end(), res[0].begin(), ::tolower);
		ret[res[0]] = uint64_t(std::stoull(res[1], nullptr, 16));
	}	
	return ret;
}


std::vector<uint64_t> LocateCudaSynchronization::IdentifySyncFunction() {
	// Strategy: look at various 
	std::string cudaName = FindLibCuda().string();
	BPatchBinary bin(cudaName, false, std::string("DONOTWRITE"));
	std::vector<uint64_t> ret = bin.FindSyncCandidates();
	return ret;
}

void LocateCudaSynchronization::WriteSyncLocation(uint64_t addr) {
	std::string md5cuda = GetMD5Sum(FindLibCuda());
	std::fstream fs;
  	fs.open(std::string(LOCAL_INSTALL_PATH) + std::string("/lib/SyncDriverVerisons.txt"), std::fstream::out | std::fstream::app);
  	fs << md5cuda << "$0x" << std::hex << addr << std::dec << std::endl;
  	fs.close();
}

std::string LocateCudaSynchronization::GetMD5Sum(boost::filesystem::path file) {
	/**
	 * Get the md5sum of the file supplied in file. returns a string repre
	 */
    #ifdef DEBUG_LOCATECUDA
    std::cout << "[LocateCudaSynchronization::GetMD5Sum] Hashing libcuda at location: " << file.string() << std::endl;
    #endif
	unsigned char result[MD5_DIGEST_LENGTH];
	int fd = open(file.string().c_str(), O_RDONLY);
	if (fd == -1 )
		return std::string("");

    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) return std::string("");	
    size_t fileSize = statbuf.st_size;

    char * file_buf = (char *) mmap(0, fileSize, PROT_READ, MAP_SHARED, fd, 0);
    MD5((const unsigned char *) file_buf, fileSize, result);
    munmap(file_buf, fileSize);
    close(fd);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    	ss << std::setfill('0') << std::setw(2) << std::hex << (int)(result[i]);
    }
    std::string ret = ss.str();
    std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
    #ifdef DEBUG_LOCATECUDA
    std::cout << "[LocateCudaSynchronization::GetMD5Sum] Hash Value Calculated for " << ret << std::endl;
    #endif
    return ret;
}


boost::filesystem::path LocateCudaSynchronization::FindLibCuda() {
	/**
	 * Finds the system version of libcuda by searching LD_LIBRARY_PATH
	 *
	 * Returns: 
	 */
	boost::filesystem::path ret; 
	std::vector<std::string> dirs;
	std::string env_p = std::string(std::getenv("LD_LIBRARY_PATH"));
	StringSplit(env_p, ':', dirs);

	// Adding some special locations
	dirs.push_back("/lib64");
	dirs.push_back("/usr/lib64");

	for (auto i : dirs) {
		std::vector<std::string> files;
		std::cerr << "Searching directory: " << i << std::endl;
		GetFilesInDirectory(i, files);
		for (auto file : files){
			//std::cerr << "File: " << file << std::endl;
			if (file.find("libcuda.so") != std::string::npos){
				ret /= file;
				return ret;
			}
		}
	}
	return ret;
}
