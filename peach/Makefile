# See peach/COPYRIGHT for copyright information.
#
# Peach is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 3.0 of the License, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
# 
# You should have received a copy of the GNU Lesser General Public License
# along with this software; if not, see www.gnu.org/licenses

# This is the makefile for peach, the disassembly fuzzer.
#
# Call this file using "make peach" after configuring paths to the necessary 
# tools below.

# This variable should contain a path (relative or absolute) to the install
# location of Dyninst 9.x or later.
dyn := /p/paradyn/development/holcomb/tools/dyninst/install

# Place the path (relative or absolute) to XED below.
xed := /p/paradyn/development/holcomb/tools/xed

# Path to LLVM
llvm := /p/paradyn/development/holcomb/tools/LLVM/install

# Path to Binutils
binutils := /u/h/o/holcomb/private/binutils/install
#binutils := /p/paradyn/development/holcomb/tools/binutils/install

# Compiler to use.
CXX_COMPILER := g++

# Flags passed to the compiler
CC_FLAGS := -g -std=c++0x

# The objects that peach relies on.
objects := util/MappedInst.o
objects += util/Mystring.o
objects += util/MapTable.o
objects += util/BitTypes.o
objects += util/BitTypeMap.o
objects += util/Hashcounter.o
objects += util/Options.o
objects += util/Info.o
objects += util/Alias.o
objects += util/Mask.o
objects += util/RegisterSet.o
objects += util/Architecture.o
objects += util/Bitfield.o

objects += decoders/dyninst_aarch64.o
objects += decoders/dyninst_x86_64.o
objects += decoders/llvm_aarch64.o
objects += decoders/llvm_x86_64.o
objects += decoders/llvm_common.o
objects += decoders/gnu_x86_64.o
objects += decoders/gnu_aarch64.o
objects += decoders/xed_x86_64.o
objects += decoders/null_decoders.o
objects += decoders/Decoder.o

objects += decoders/Normalization.o

objects += reporting/ReportingContext.o

utilinc = -Iutil
decoderinc = -Idecoders
reportinginc = -Ireporting

xedlib := -L$(xed)/lib
xedinc := -I$(xed)/include

dynlib := -L$(dyn)/lib
dyninc := -I$(dyn)/include

llvmlib := -L$(llvm)/lib
llvminc := -I$(llvm)/include

binutilslib := -L$(binutils)/lib
binutilsinc := -I$(binutils)/include

alllib := $(xedlib) $(dynlib) $(llvmlib) $(binutilslib)
allinc := $(utilinc) $(decoderinc) $(xedinc) $(dyninc) $(llvminc) $(binutilsinc) $(reportinginc)

all: clean peach CombineReports

default: all

clean:
	rm -f peach peach.o CombineReports CombineReports.o $(objects)

peach: $(objects)
	$(CXX_COMPILER) $(CC_FLAGS) $(allinc) $(alllib) -o peach peach.C $(objects) -linstructionAPI -lxed -lLLVM -lopcodes -lrt -lbfd -liberty -ldl -lz

CombineReports: $(objects)
	$(CXX_COMPILER) $(CC_FLAGS) $(allinc) $(alllib) -std=c++0x -o CombineReports CombineReports.C $(objects) -linstructionAPI -lxed -lLLVM -lopcodes -lrt -lbfd -liberty -ldl

.C.o:
	$(CXX_COMPILER) $(CC_FLAGS) -c -o $@ -c $< $(allinc)

