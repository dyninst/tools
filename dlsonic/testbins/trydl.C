#include <iostream>
#include <dlfcn.h>
#include <string.h>

// Most basic case when the string is read from .rodata
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

// Slightly trickier variant of type1
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

// Libname passed as function parameter, there is no easy way to
// handle this case.
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

// Ideally we should be able to trace the value of data here.
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

// In this example, the library name is read from .data instead of
// .rodata section.
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

// Case prepared to understand and handling strcpy.
// In prod software we can expect path and library names to be appended
// together (and copied to a buffer).
void type6()
{
    strcpy( data, "libhello" );
    strcat( data, ".so" );
     auto hdl = dlopen( data, RTLD_LAZY );
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
    (*fptr)( "type6" );
    dlclose( hdl );
}   

// Basic case for dlmopen
void type7()
{
    auto hdl = dlmopen( LM_ID_BASE, "libhello.so", RTLD_LAZY );
    if ( ! hdl ) {
        printf("failed to open libhello.so");
        return;
    }
    void (*fptr)( const char * );
    *(void**)(&fptr) = dlsym( hdl, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s\n", error );
        return;
    }
    (*fptr)( "type7" );
    dlclose( hdl );
}

// Most basic case when the string is read from .rodata
void type8()
{
    auto hdl = dlopen( "libhello.so", RTLD_LAZY );
    if ( ! hdl ) {
        printf( "failed to open libhello.so" );
        return;
    }
    void (*fptr)( const char* );

    *(void**)(&fptr)  = dlvsym( hdl, "_Z3fooPKc", "LIB_V1" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s", error ); 
        return;
    }
    (*fptr)( "type8" );
    dlclose( hdl );
}

void type9()
{
    void (*fptr)( const char* );
    *(void**)(&fptr)  = dlsym( RTLD_DEFAULT, "_Z3fooPKc" );

    char* error = dlerror();
    if ( error ) {
        printf( "ERROR: %s", error ); 
        return;
    }
    (*fptr)( "type8" );
}

int main()
{
    type1();
    type2();
    type3( "libhello.so" );
    type4();
    type5();
    type6();
    type7();
    type8();
    type9();
    return 0;
}
