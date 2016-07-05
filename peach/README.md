See COPYRIGHT for copyright information.

This file is a part of Peach.

Peach is free software; you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3.0 of the License, or (at your option)
any later version.

This software is distributed in the hope that it will be useful, but WITHOUT 
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License
along with this software; if not, see www.gnu.org/licenses

# Peach

Peach is a fuzzing tool used to compare assembly decoders. Currently LLVM, binutils (libopcodes) and dyninst are supported.

## Building Dependancies

Peach depends on the following libraries:

- libopcodes, libbfd (bintuils)
- libxed
- libz
- libinstructionAPI (dyninst)
- LLVM
- libiberty
- libdl

### Xed

Xed can be downloaded from here: https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library

Once this is downloaded and unzipped, it can be installed with:

```
sudo cp kits/<XED VERSION+PLATFORM>/lib/* $PREFIX/lib64
```

### Binutils

Binutils can be obtained from a gnu mirror, such as ftp://ftp.gnu.org/gnu/binutils. You may also build the latest version via the git repo: 

```
git clone git://sourceware.org/git/binutils-gdb.git
```

We recommend that you build binutils from source. You MUST have a version of binutils that has been configured with `--enable-targets=all`. To build binutils from source:

```
mkdir build
cd build
../bintuils-gdb/configure --enable-targets=all --enable-shared --prefix=$PREFIX --prefix=$PREFIX/lib64
make
make install
```

### Dyninst

Dyninst can be obtained from the github repository:

```
git clone http://github.com/dyninst/dyninst
```

To build dyninst:

```
# Use the gui configuration to set prefix, build-type, ect.
cd dyninst/
ccmake .
make
make install
```

## Building Peach

Make sure your `LD_LIBRARY_PATH` is pointing at the dependancies before you attempt to compile peach. This doesn't need to be set if the dependancies are installed globally under `/usr/lib64`

Peach can also be built using CMake:

```
ccmake .
make
make install
```

For help with peach, execute:

./peach --help
