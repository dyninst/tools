#include <iostream>
#include <dlfcn.h>
#include <string.h>

void type1()
{
    auto hdl = dlopen( "libhello.so", RTLD_LAZY );
    if ( ! hdl ) {
        printf( "failed to open libhello.so" );
        return;
    }
    void (*fptr)( const char* );

    *(void**)(&fptr)  = dlsym( hdl, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s", error ); 
        return;
    }
    (*fptr)( "type1" );
    dlclose( hdl );
}

void type2()
{
    const char* libname = "libhello.so";
    auto hdl = dlopen( libname, RTLD_LAZY );
    if ( ! hdl ) {
        printf( "failed to open libhello.so\n" );
        return;
    }
    void (*fptr)( const char* );
    *(void**)(&fptr) = dlsym( hdl, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s\n", error ); 
        return;
    }
    (*fptr)( "type2" );
    dlclose( hdl );
}

void type3( const char* libname )
{
    auto hdl = dlopen( libname, RTLD_LAZY );
    if ( ! hdl ) {
        printf( "failed to open %s\n", libname );
        return;
    }
    void (*fptr)( const char* );
    *(void**)(&fptr) = dlsym( hdl, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s\n", error ); 
        return;
    }
    (*fptr)( "type3" );
    dlclose( hdl );
}

char data[100];

void type4()
{
    strcpy(data, "libhello.so");
    auto hdl = dlopen( data, RTLD_LAZY );
    if ( ! hdl ) {
        printf("failed to open libhello.so\n");
        return;
    }
    void (*fptr)( const char* );
    *(void**)(&fptr) = dlsym( hdl, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) { 
        printf( "ERROR: %s\n", error ); 
        return;
    }
    (*fptr)( "type4" );
    dlclose( hdl );
}

const char* globallibname = "libhello.so";

void type5()
{
    auto hdl = dlopen( globallibname, RTLD_LAZY );
    if ( ! hdl ) {
        printf("failed to open %s\n", globallibname);
        return;
    }
    void (*fptr)( const char* );
    *(void**)(&fptr) = dlsym( hdl, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s\n", error );
        return;
    }
    (*fptr)( "type5" );
    dlclose( hdl );
}

int main()
{
    type1();
    type2();
    type3( "libhello.so" );
    type4();
    type5();
    return 0;
}
