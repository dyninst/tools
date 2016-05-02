#ifndef DYNINST_AARCH64_DRIVER_H
#define DYNINST_AARCH64_DRIVER_H

#include <string>
#include <vector>

namespace Dyninst_aarch64 {

class Driver
{
public:
    Driver();

    std::string streamname;

    bool parse_stream(std::istream& in,
		      const std::string& sname = "stream input");

    bool parse_string(const std::string& input,
		      const std::string& sname = "string stream");

    bool parse_file(const std::string& filename);

    void error(const class location& l, const std::string& m);

    void error(const std::string& m);

    class Scanner* lexer;

};

} // namespace example

#endif // EXAMPLE_DRIVER_H
