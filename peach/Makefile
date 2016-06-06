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

# Build type: DEBUG or RELEASE
BUILD_TYPE := DEBUG

# This variable should contain a path (relative or absolute) to the install
# location of Dyninst 9.x or later.
# dyn := /p/paradyn/development/holcomb/tools/dyninst/install

# Place the path (relative or absolute) to XED below.
# xed := /p/paradyn/development/holcomb/tools/xed

# Path to LLVM
llvm := /p/paradyn/development/holcomb/tools/LLVM/install

# Path to Binutils
# binutils := /u/h/o/holcomb/private/binutils/install
#binutils := /p/paradyn/development/holcomb/tools/binutils/install

# Configuration
CC := gcc
CFLAGS := -Werror
CXX := g++
CXXFLAGS := -std=c++0x

DEBUGFLAGS := -ggdb

ifeq ($(BUILD_TYPE), "DEBUG")
	CXXFLAGS := $(CXXFLAGS) $(DEBUGFLAGS)
	CFLAGS := $(CFLAGS) $(DEBUGFLAGS)
endif

UTIL_OBJECTS := \
	MappedInst \
	Mystring \
	MapTable \
	BitTypes \
	BitTypeMap \
	Hashcounter \
	Options \
	Info \
	Alias \
	Mask \
	RegisterSet \
	Architecture \
	Bitfield
UTIL_OBJECTS := $(addprefix util/, $(UTIL_OBJECTS))
UTIL_OBJECTS := $(addsuffix .o, $(UTIL_OBJECTS))

DECODER_OBJECTS := \
	dyninst_aarch64 \
	dyninst_x86_64 \
	llvm_aarch64 \
	llvm_x86_64 \
	llvm_common \
	gnu_x86_64 \
	gnu_aarch64 \
	xed_x86_64 \
	null_decoders \
	Decoder \
	Normalization
DECODER_OBJECTS := $(addprefix decoders/, $(DECODER_OBJECTS))
DECODER_OBJECTS := $(addsuffix .o, $(DECODER_OBJECTS))

REPORTING_OBJECTS := \
	ReportingContext
REPORTING_OBJECTS := $(addprefix reporting/, $(REPORTING_OBJECTS))
REPORTING_OBJECTS := $(addsuffix .o, $(REPORTING_OBJECTS))

OBJECTS := \
	$(UTIL_OBJECTS) \
	$(DECODER_OBJECTS) \
	$(REPORTING_OBJECTS)

INCLUDES := \
		   -Iutil \
		   -Idecoders \
		   -Ireporting
LIBS := \
	z \
	instructionAPI \
	xed \
	LLVM \
	opcodes \
	rt \
	bfd \
	iberty \
	dl
LIBS := $(addprefix -l, $(LIBS))


.PHONY: all clean
all: peach CombineReports

clean:
	rm -f peach CombineReports CombineReports.o $(OBJECTS)

peach: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o peach peach.C $(OBJECTS) $(LIBS)

CombineReports: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -std=c++0x -o CombineReports CombineReports.C $(OBJECTS) $(LIBS)

.C.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<
