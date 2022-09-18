#include <iostream>
#include "hello_lib_header.H"

void foo( const char* msg )
{
    std::cout << "Foo was called - yay!: " << std::string(msg) << std::endl;
}
