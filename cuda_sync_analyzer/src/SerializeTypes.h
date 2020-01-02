#pragma once
#include <string.h>
#include <algorithm>
#include <functional>
#include <array>
#include <iostream>
#include <cassert>
#include <deque>
#include <sys/time.h>
#include <cstdlib>
#include <sstream>
#include <tuple>
#include <utility> 
#include <stdarg.h>
#include <map>
#include <set> 
#include <iomanip>
#include <string>
#include <cassert>
#include <sys/types.h>
#include <unistd.h>
#include <mutex>
#include <queue>
#include <boost/program_options.hpp>


uint64_t SerializeUint64(FILE * fp, uint64_t val);
void ReadUint64(FILE * fp, uint64_t & val);
uint64_t SerializeSring(FILE * fp, std::string & str);
void DeserializeString(FILE * fp, std::string & ret);
uint64_t SerializeBool(FILE * fp, bool b);
void DeserializeBool(FILE * fp, bool & b);
