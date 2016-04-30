//
// Created by cygnus on 4/29/2016.
//

#include <fstream>
#include "Driver.h"
#include "Scanner.h"

namespace Dyninst_aarch64 {
    bool Driver::parse_stream(std::istream &in) {
        Scanner scanner;
        this->lexer = &scanner;

        Parser parser(*this);

        return parser.parse() == 0;
    }

    bool Driver::parse_file(const std::string &filename) {
        std::ifstream in(filename.c_str());
        if(!in.good())
            return false;

        return parse_stream(in);
    }
}

