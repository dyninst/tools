#include <cstdio>
#include "hello_lib_header.H"

__asm__(".symver _Z3fooPKc,_Z3fooPKc@LIB_V1");
__asm__(".symver _Z4fooPKc,_Z4foo2PKc@LIB_V2");

void foo( const char* msg )
{
    printf("Foo was called: %s\n", msg);
}

void foo2( const char* msg )
{
    printf("Foo2 was called: %s\n", msg);
}
