#pragma once
#include <cstdlib>
#include <sys/types.h>
#include <dirent.h>
#include <string>
#include <map>
#include <sstream> 
#include <vector>
#include <boost/filesystem.hpp>
#include <fstream>
bool CheckIfFileExists(const std::string & name);
void StringSplit(const std::string &s, char delim, std::vector<std::string> & result);
void GetFilesInDirectory(std::string & dir, std::vector<std::string> & files);