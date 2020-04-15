### User Manual
https://docs.google.com/document/d/1h12Uq-cQyNSRuajZQo9bhcpFFPZVmL1g-ztCRifze5s

### External Dependencies
* Dyninst - https://github.com/dyninst/dyninst
* Boost C++ Libraries (tested with version 1.61)
* CUDA (tested with 4xx series GPU driver versions)

### Build and Install

Build and install Dyninst if it isn’t already installed - https://github.com/dyninst/dyninst/wiki/Building-Dyninst
```
$ export LD_LIBRARY_PATH=<DYNINST_INSTALL_PREFIX>/lib/:<BOOST_INSTALL_PREFIX>/install/lib/:/usr/lib/x86_64-linux-gnu/
$ export DYNINSTAPI_RT_LIB=<DYNINST_INSTALL_PREFIX>/lib/libdyninstAPI_RT.so
$ git clone https://github.com/dyninst/tools.git
$ cd tools/cuda_sync_analyzer
$ mkdir build && cd build
$ cmake ..  \
  -DDYNINST_ROOT=<DYNINST_INSTALL_PREFIX> \
  -DCUDA_TOOLKIT_ROOT_DIR=/usr/local/cuda \
  -DBOOST_LIBRARYDIR=<BOOST_INSTALL_PREFIX>/install/lib \
  -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo \
  -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
  -DCMAKE_INSTALL_PREFIX=<INSTALL_PREFIX>
$ make && make install
```
