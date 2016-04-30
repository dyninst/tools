//
// Created by cygnus on 4/29/2016.
//

#ifndef SEMANTICS_BROAD_TEST_DRIVER_H
#define SEMANTICS_BROAD_TEST_DRIVER_H

#include <string>

namespace Dyninst_aarch64 {
    class Driver {
    public:
        bool parse_stream(std::istream &in);
        bool parse_file(const std::string &filename);
        class Scanner *lexer;
    };
}

#endif //SEMANTICS_BROAD_TEST_DRIVER_H
