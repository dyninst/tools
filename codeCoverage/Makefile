#
# A GNU Makefile
#
# This Makefile builds the codeCoverage Dyninst mutator
#

# Make sure to set the DYNINST_ROOT environment variable to the directory where
# Dyninst is installed. The directory should contain the include and
# $(PLATFORM)/lib directories

# Or uncomment the following line and change the path accordingly
# DYNINST_ROOT = /change/me

ifeq ($(DYNINST_ROOT),)
$(error DYNINST_ROOT is not set)
endif

ifeq ($(PLATFORM),)
$(error PLATFORM is not set)
endif

DYNINST_INCLUDE = $(DYNINST_ROOT)/$(PLATFORM)/include
DYNINST_LIB =  $(DYNINST_ROOT)/$(PLATFORM)/lib

CXX = g++
CXXFLAGS = -g -Wall -std=c++11
LIBFLAGS = -fpic -shared

CC = gcc
CFLAGS = -Wall -pedantic -g 

all: codeCoverage libInst.so testcc

codeCoverage: codeCoverage.o
	$(CXX) $(CXXFLAGS) -L$(DYNINST_LIB) \
		-o codeCoverage codeCoverage.o \
		-lcommon \
		-ldyninstAPI \
		-lpthread \

codeCoverage-static: codeCoverage.o
	$(CXX) $(CXXFLAGS) -I$(DYNINST_INCLUDE) -L$(DYNINST_LIB) \
		-o codeCoverage-static codeCoverage.o \
		-Wl,-Bstatic \
		-ldyninstAPI \
		-lpatchAPI -lparseAPI -lstackwalk \
		-lsymLite -lsymtabAPI -ldynElf -ldynDwarf -linstructionAPI -lpcontrol \
		-ldw -lelf \
		-lcommon \
		-liberty \
		-Wl,-Bdynamic \
		-pthread \
		-ldl 

libInst.so: libInst.C
	$(CXX) $(CXXFLAGS) $(LIBFLAGS) libInst.C -o libInst.so  

codeCoverage.o: codeCoverage.C
	$(CXX) $(CXXFLAGS) -I$(DYNINST_INCLUDE) -c codeCoverage.C

libtestcc.so: libtestcc.c libtestcc.h
	$(CC) $(CFLAGS) $(LIBFLAGS) -o libtestcc.so libtestcc.c

testcc: libtestcc.so testcc.c
	$(CC) $(CFLAGS) -o testcc testcc.c ./libtestcc.so

clean:
	rm -f codeCoverage codeCoverage-static testcc *.so *.o testcc.inst
