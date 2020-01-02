##### Build and Install

```
export LD_LIBRARY_PATH=<DYNINST_INSTALL_PREFIX>/lib/:<BOOST_INSTALL_PREFIX>/install/lib/:/usr/lib/x86_64-linux-gnu/
export DYNINSTAPI_RT_LIB=/nobackup/nisargs/dyninst-project/dyninst-install/lib/libdyninstAPI_RT.so

cmake .. \
  -DDYNINST_ROOT=/nobackup/nisargs/dyninst-project/dyninst-install/ \
  -DCUDA_TOOLKIT_ROOT_DIR=/usr/local/cuda \
  -DBOOST_LIBRARYDIR=/nobackup/nisargs/diogenes-project/boost_1_61_0/install/lib \
  -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo \
  -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
  -DCMAKE_INSTALL_RPATH_USE_LINK_PATH:BOOL=FALSE \
  -DCMAKE_INSTALL_PREFIX=<INSTALL PREFIX> && make install
```

##### Run

```
<INSTALL_PREFIX>/bin/main
```
