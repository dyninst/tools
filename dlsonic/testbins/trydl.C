#include <iostream>
#include <dlfcn.h>


void type1()
{
    auto hdl = dlopen("libhello.so", RTLD_LAZY);
    if ( ! hdl ) {
        std::cerr << "failed to open libhello" << std::endl;
    }
    void (*fptr)( const char* );

    *(void**)(&fptr)  = dlsym(hdl, "_Z3fooPKc");

    char* error = dlerror();
    if ( error ) {
        std::cerr << "ERROR: " << std::string(error) << std::endl;
        return;
    }
    (*fptr)( "type1" );
    dlclose(hdl);
}

void type2()
{
    const char* libname = "libhello.so";
    auto hdl = dlopen( libname, RTLD_LAZY );
    if ( ! hdl ) {
        std::cerr << "failed to open libhello" << std::endl;
    }
    void (*fptr)( const char* );
    *(void**)(&fptr) = dlsym(hdl, "_Z3fooPKc");

    char* error = dlerror();
    if ( error ) {
        std::cerr << "ERROR: " << std::string(error) << std::endl;
        return;
    }
    (*fptr)( "type2" );
    dlclose(hdl);
}

void type3( const char* libname )
{
    auto hdl = dlopen( libname, RTLD_LAZY );
    if ( ! hdl ) {
        std::cerr << "failed to open libhello" << std::endl;
    }
    void (*fptr)( const char* );
    *(void**)(&fptr) = dlsym(hdl, "_Z3fooPKc");

    char* error = dlerror();
    if ( error ) {
        std::cerr << "ERROR: " << std::string(error) << std::endl;
        return;
    }
    (*fptr)( "type3" );
    dlclose(hdl);
}



int main()
{
    type1();
    type2();
    type3( "libhello.so" );
    return 0;
}
