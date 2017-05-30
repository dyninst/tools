
#include <stdio.h>
#include "Architecture.h"

Architecture* Architecture::currentArch = NULL;
std::unordered_map<const char*, Architecture*, StringUtils::str_hash, StringUtils::str_eq> Architecture::architectures;

Architecture::Architecture(const char* name, int maxInsnLen, bool (*initFunc)(void)) {
    this->name = strdup(name);
    this->maxInsnLen = maxInsnLen;
    this->initFunc = initFunc;
    architectures.insert(std::make_pair(name, this));
}

void Architecture::init(const char* arch) {
    auto archEntry = architectures.find(arch);
    if (archEntry != architectures.end()) {
        currentArch = archEntry->second;
        bool success = (*(currentArch->initFunc))();
        if (!success) {
            std::cerr << "ERROR: Could not initialize architecture: " << currentArch->name << "\n";
            exit(-1);
        }
    } else {
        std::cerr << "UNKNOWN ARCHITECTURE: " << arch << "\n";
        std::cerr << "Valid options are:\n";
        auto it = architectures.begin();
        while (it != architectures.end()) {
            std::cerr << "\t" << it->second->name << "\n";
            ++it;
        }
        exit(-1);
    }
}

void Architecture::addRegSet(RegisterSet* regSet) {
    std::vector<const char*> nameList = regSet->getNameList();
    const char* sym = regSet->getSymbol();
    for (size_t i = 0; i < nameList.size(); ++i) {
        currentArch->regSymbolMap.insert(std::make_pair(nameList[i], sym));
    }
}

void Architecture::replaceRegSets(FieldList& fl) {
    for (size_t i = 0; i < fl.size(); ++i) {
        auto name = currentArch->regSymbolMap.find(fl.getField(i));
        if (name != currentArch->regSymbolMap.end()) {
            fl.setField(i, name->second);
        }       
    }
}
