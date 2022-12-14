# Survey of source codes for common dlopen/dlsym idioms

This report contains our observations while looking at source codes for various tools and libraries which are known to have dlopen/dlsym usage but our tool, in its current state, is not able to derive a lot more information beyond this. The goal is understand if there are any programming idioms and patterns that show up when working with these system calls. In an ideal case, supporting commonly used idioms and patterns will allow us to uncover new knowledge and insights.

## 1. Wrappers

We consider a function involving dlopen/dlsym a wrapper if the arguments to the dlopen/dlsym calls are coming largely from the arguments of this wrapping function. Wrapper does minimal work - although we expect error checking, logging, and preprocessing/formatting of library names (including prepending a path).

The qualifying criterion for a function to be called a 'wrapper' is that atleast one of the key inputs like module/library name or symbol should come from the arguments. 

### A. Wrapping either dlopen or dlsym call
A wrapper that wraps around dlopen or dlsym call. Typically a dlopen wrapper will accept the library name string and return handle returned by the dlopen call. Such a wrapper is expected to do basic sanity checking (like checking for `NULL` handle in case of dlsym) and/or preprocessing (like appending path to the library name in case of dlopen).

```cpp
// The following example is from zsh Src/module.c
static void *
try_load_module(char const *name)
{
    char buf[PATH_MAX + 1];
    char **pp;
    void *ret = NULL;
    int l;

    l = 1 + strlen(name) + 1 + strlen(DL_EXT);
    for (pp = module_path; !ret && *pp; pp++) {
	if (l + (**pp ? strlen(*pp) : 1) > PATH_MAX)
	    continue;
	sprintf(buf, "%s/%s.%s", **pp ? *pp : ".", name, DL_EXT);
	unmetafy(buf, NULL);
	if (*buf) /* dlopen(NULL) returns a handle to the main binary */
	    ret = dlopen(buf, RTLD_LAZY | RTLD_GLOBAL);
    }
    return ret;
}

```

### B. Wrapping a full dlopen-dlsym usage pattern
This one is expected to be used less often compared to 1A. The idea is to wrap around a complete dlopen and dlsym usage. Within the wrapper, we will find a dlopen call followed by a subsequent dlsym call using the returned handle.

```cpp
// representative example
information_t load_and_try( const char* libname, const char* symname )
{
    // preprocess
    // dlopen:
    auto handle = dlopen( libname, ... );
    // error handling
    // dlsym:
    auto ptr = dlsym( handle, symname, ... );
    // more error handling
    // use ptr to do something and prepare to return
    return information_t { ... };
}
```

It's important to note that this usage pattern is hard to identify at times. But we must stick to the basic definition of wrappers and try to figure out whether the libname or symname are coming from the arguments before concluding.

A common variation is to hardcode the symname to a commonly used symname like `C_GetFunctionList`.

## 2. Handle as class member
In general, I have seen this style in a couple of Android related code / frameworks. Flow goes something like as follows:
```cpp
class DemoClass
{
public:
    void tryOpen( ... ) {
        // ...
        if ( ! dlhandle_ ) {
            dlhandle_ = dlopen( ... );
        }   
    }
    void tryAccess( ... ) {
        // ...
        auto ptr = dlsym( dlhandle_, ... ); 
    }
private:
    void* dlhandle_;
};
```

## 3. Global Handle
An intuitive expansion of the above approach, where instead of the class the handle is stored in a global variable.

```cpp
// global
void* glHandle = nullptr;

    // somewhere in code
    glHandle = dlopen( ... );

    // somewhere else in code
    auto ptr = dlsym( glHandle, ... ); 
```
It is easy to guess that this pattern may be combined with one of the wrapper patterns.

## 4. TBD


## Examples
| # | Where       | Classification | Comments |
| - | ----------- | -------------- | -------- |
| 1 | zsh         | Wrapper A      | our current slicing based argument tracking won't even be able to get the libname since it is being copied to a buffer|
| 2 | make        | Wrapper B      | [load_object](https://github.com/wkusnierczyk/make/blob/master/load.c#L48) |
| 3 | libpkcs  | Wrapper B      | with hardcoded symname |
| 4 | dmeventd.c | Wrapper B* | [Source](https://android.googlesource.com/platform/external/lvm2/+/d44af0be2c6f4652eafd90a70e7ba5f24c0f6d5a/daemons/dmeventd/dmeventd.c), * it is hard to figure out the input here since the input arg is a struct and libname string is read from this struct. |
| 5 | rsyslogd | Wrapper B | [Source](https://github.com/rsyslog/rsyslog/blob/master/runtime/modules.c#L1088) |
| 6 | libvulkan | Class Member Handle | [Source](https://android.googlesource.com/platform/frameworks/native/+/master/vulkan/libvulkan/layers_extensions.cpp) |
| 7 | libEGL | Wrapper A | dlopen is wrapped, dlsyms are called with symbol name passed as arguments to containing function (so also a wrapper) | 
| 8 | /usr/bin/DistanceEst | - | dlsym with RTLD_NEXT and static str symbol |
| 9 | /usr/bin/xbrlapi | Wrapper A | Wrapper for both dlopen and dlsym |
| 10 | /usr/bin/brltty-ttb | Wrapper A | Wrapper for both dlopen and dlsym |
| 11 | /usr/bin/abyss-fixmate | - | dlsym with RTLD_NEXT and static str symbol |
| 12 | /usr/bin/luatex | Wrapper B | - |
| 13 | libuno_sal.so | Wrapper B | - |
| x | tmp | tmp | tmp |
| x | tmp | tmp | tmp |
| x | tmp | tmp | tmp |
| x | tmp | tmp | tmp |