See COPYRIGHT for copyright information.

This file is a part of Fleece.

Fleece is free software; you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3.0 of the License, or (at your option)
any later version.

This software is distributed in the hope that it will be useful, but WITHOUT 
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License
along with this software; if not, see www.gnu.org/licenses

# Fleece

Fleece is a fuzzing tool used to compare instruction decoders. Currently, testing decoders for
x86 (32 and 64 bit), ARMv8 and PowerPC (32 and 64 bit) are supported. Fleece includes source files
that allow users to easily test XED, LLVM, binutils (libopcodes), capstone and dyninst, provided
that the tools are installed.

For information on adding a new decoder or architecture, see docs/AddingDecoders.txt or
docs/AddingArchitectures.txt.

## Building Fleece

Fleece should be built using CMake:

```
ccmake .
make
make install
```


## Example Usage of Fleece

Below are some example uses of Fleece:

```
./fleece -arch=x86_64 -as=/usr/bin/as -decoders=xed,dyninst -n=10
```
This example will test x86 (64 bit) decoding of XED and Dyninst starting with 10 random byte
sequences and exploring new options by mapping instructions and mutating them to produce new
inputs. Reassembly is performed by /usr/bin/as.

```
./fleece -arch=ppc -as=/usr/bin/ppc_as -asopt=-mpower9,-mregnames -decoders=llvm,dyninst,gnu -n=10
```

This example tests 32 bit PowerPC decoding of LLVM, Dyninst and GNU's libopcodes, again using 10
random byte sequences and exploring from there. Reassembly is performed by /usr/bin/ppc\_as, which
should be a PowerPC assembler. The assembler will recieve the optional arguments "-mpower9
-mregnames".

```
./fleece -arch=aarch64 -as=/usr/bin/aarch64_as -decoders=llvm,dyninst -n=100 -rand
-mask=0000000011111111xxxxxxxx00000000
```

This example tests Aarch64 (ARMv8) decoding of LLVM and Dyninst using 100 byte sequences. The byte
sequences will each be one byte of 0s, one byte of 1s, one byte of random bits and one byte of 0s, as
described by the mask. This basically fuzzes over the 3rd byte of the instruction while holding the
others constant. Reassembly is performed by /usr/bin/aarch64\_as. Note that the "-rand" flag means
that only random input sequences will be used, so no new instructions will be discovered.

For additional Fleece options, execute:

./fleece --help

