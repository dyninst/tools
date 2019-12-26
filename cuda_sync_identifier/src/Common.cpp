#include "Common.h"

void StringSplit(const std::string &s, char delim, std::vector<std::string> & result) {
	/** 
	 * StringSplit : Splits a string by delim, returns result in vector form as result.
	 *
	 * Could be made more efficient but this works for general cases (and keeps bloat down).
	 */
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        result.push_back(item);
    }
}
bool CheckIfFileExists (const std::string& name) {
    std::ifstream f(name.c_str());
    return f.good();
}

void GetFilesInDirectory(std::string & dir, std::vector<std::string> & files) {
	/** 
	 * Returns all files in a given directory, this is a non-recursive return.
	 */
	struct dirent *dp;
	DIR * d = opendir(dir.c_str());
	if (d == NULL)
		return;
	while ((dp = readdir (d)) != NULL) {
		boost::filesystem::path ret(dir);
		ret /= dp->d_name;
		files.push_back(ret.string());
	}
}
