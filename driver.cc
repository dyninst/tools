#include <fstream>
#include <sstream>

#include "driver.h"
#include "scanner.h"

namespace Dyninst_aarch64 {

    bool Driver::pcode_parse(const std::string &filename) {
        std::ifstream in(filename.c_str());
        if (!in.good())
            return false;

        Scanner scanner(&in);
        this->scanner = &scanner;

        Parser parser(*this);
        return (parser.parse() == 0);
    }

    void Driver::error(const class location &l,
                       const std::string &m) {
        std::cerr << l << ": " << m << std::endl;
    }

    void Driver::error(const std::string &m) {
        std::cerr << m << std::endl;
    }

}
