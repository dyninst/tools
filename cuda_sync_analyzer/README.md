##### About
Dynamically instrument CUDA programs to profile synchronization primitives

##### Build and Install

```
export LD_LIBRARY_PATH=<DYNINST_INSTALL_PREFIX>/lib/:<BOOST_INSTALL_PREFIX>/install/lib/:/usr/lib/x86_64-linux-gnu/
export DYNINSTAPI_RT_LIB=/nobackup/nisargs/dyninst-project/dyninst-install/lib/libdyninstAPI_RT.so

git clone https://github.com/dyninst/tools.git
cd tools/cuda_sync_analyzer
mkdir build && cd build
cmake ..  \
  -DDYNINST_ROOT=<DYNINST_INSTALL_PREFIX> \
  -DCUDA_TOOLKIT_ROOT_DIR=/usr/local/cuda \
  -DBOOST_LIBRARYDIR=<boost install/lib directory> \
  -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo \
  -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
  -DCMAKE_INSTALL_PREFIX=<INSTALL_PREFIX>
make && make install
```

##### Run

```
Usage: <INSTALL_PREFIX>/bin/mutateLibcuda <target mutated libcuda>
LD_PRELOAD=<target mutated libcuda> <path to executable>libcuda.so.1> <path to CUDA application>
```
