#ifndef DYNINST_AARCH64_DRIVER_H
#define DYNINST_AARCH64_DRIVER_H

#include <string>
#include <vector>

namespace Dyninst_aarch64 {

    class Driver {
    public:
        bool pcode_parse(const std::string &filename);

        void error(const class location &l, const std::string &m);

        void error(const std::string &m);

        class Scanner *scanner;

    };

} // namespace example

#endif // EXAMPLE_DRIVER_H
