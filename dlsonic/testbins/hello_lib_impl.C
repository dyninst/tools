#include <cstdio>
#include "hello_lib_header.H"

__asm__(".symver _Z3fooPKc,_Z3fooPKc@");
__asm__(".symver _Z3fooPKc,_Z3fooPKc@LIB_V1");
__asm__(".symver _Z3fooPKc,_Z3fooPKc@@LIB_V2");

void foo( const char* msg )
{
    printf("Foo was called: %s\n", msg);
}
