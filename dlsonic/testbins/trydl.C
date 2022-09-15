#include <iostream>
#include <dlfcn.h>


int main()
{
    auto hdl = dlopen("libhello.so", RTLD_LAZY);
    if ( ! hdl ) {
        std::cerr << "failed to open libtest" << std::endl;
    }
    void (*fptr)(void);

    *(void**)(&fptr)  = dlsym(hdl, "_Z3foov");

    char* error = dlerror();
    if ( error ) {
        std::cerr << "ERROR: " << std::string(error) << std::endl;
        return 0;
    }
    (*fptr)();
    dlclose(hdl);
    return 0;
}
