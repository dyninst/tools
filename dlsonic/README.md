# dlsonic: binary analysis tool for dlopen/dlsym

## Introduction

Study of dlopen and dlsym calls is an essential step towards understanding linkage behaviour of libraries and executables. This tool makes use of binary analysis tool DynInst to study ELF files and provides details on the dlopen and dlsym usage in them.

## Quick build and run flow

```console
$ cd dlsonic
$ cmake .  -DDyninst_DIR=/path/to/dyninst-build-dir
$ make
```
The above builds the dlsonic executable along with `testbins/trydl` which can be used for doing a quick test.

```console
$ ./dlsonic testbins/trydl                                               
Processing File: testbins/trydl
CALLDETAIL:testbins/trydl=[Id=1|Addr=12d4|Type=dlopen|Param=[libhello.so]]
CALLDETAIL:testbins/trydl=[Id=2|Addr=130f|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=3|Addr=13ad|Type=dlopen|Param=[libhello.so]]
CALLDETAIL:testbins/trydl=[Id=4|Addr=13e3|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=5|Addr=147a|Type=dlopen|Param=<unknown>]
CALLDETAIL:testbins/trydl=[Id=6|Addr=14bc|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=7|Addr=156d|Type=dlopen|Param=<unknown>]
CALLDETAIL:testbins/trydl=[Id=8|Addr=15a3|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=9|Addr=163c|Type=dlopen|Param=<unknown>]
CALLDETAIL:testbins/trydl=[Id=10|Addr=1684|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=11|Addr=1754|Type=dlopen|Param=<unknown>]
CALLDETAIL:testbins/trydl=[Id=12|Addr=179c|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=13|Addr=1837|Type=dlmopen|Param=[libhello.so]]
CALLDETAIL:testbins/trydl=[Id=14|Addr=1872|Type=dlsym|Param=[_Z3fooPKc]]
CALLDETAIL:testbins/trydl=[Id=15|Addr=1908|Type=dlopen|Param=[libhello.so]]
CALLDETAIL:testbins/trydl=[Id=16|Addr=194a|Type=dlvsym|Param=[_Z3fooPKc]]
MAPPINGS:testbins/trydl=[ 2<1 4<3 6<5 8<7 10<9 12<11 14<13 16<15 ]
DIGEST:testbins/trydl=[dlopenCount=7|dlopenWithStaticString=3|dlsymCount=7|dlsymWithStaticString=7|dlvsymCount=1|dlvsymWithStaticString=1|dlmopenCount=1|dlmopenWithStaticString=1|dlsymMapped=8|dlsymWithConstHandle=0|dlvsymMapped=0|dlvsymWithConstHandle=0]

```

## Understanding output format
The lines in output are tagged as one of: `CALLDETAIL`, `MAPPINGS`, and `DIGEST`.
Each line is expresed as:
```
<TAG>:<FILENAME>=<CONTENT>
```
This format aids post-processing scripts in drawing insights from the output and generate more readable reports.

1. `CALLDETAIL`: Whenever a dlopen/dlsym/dlvsym/dlmopen call is identified in the binary, a `CALLDETAIL` is logged. The content is in the format `[ContentTag1=Value1|ContentTag2=Value2|...]` to aid parsing. The content tags are as follows:
   - `Id`: Each dlopen or dlsym call is assigned a unique id that allows understanding the mappings later on.
   - `Addr`: The address of the `call` instruction for the given call.
   - `Type`: can be either `dlopen`, `dlmopen`, `dlsym`, or `dlvsym`.
   - `Param`: A list of strings that we are able to identify as forming the library name/path in case of dlopen and symbol in case of dlsym. The value is equal to `<unknown>` if the tool is not able to identify any.
2. `MAPPINGS`: This entry is logged once per processed file. The tool tries to connect dlsym calls to corresponding dlopen calls. The content is a space separated list: `[ dlsymId1<dlopenId1 dlsymId2<dlopenId2 ... ]`.
3. `DIGEST`: This entry is also logged once per processed file and provides an overall summary of the analysis for the given file. It contains a number of statistics that the tool tracks. See the example run for a list of fields we offer.


## Generating CSV summary of multiple files
A python utility `dlsummary.py` is provided to run the tool on a list of files and generate a CSV report.

If we have a list of ELF files in `input_files.txt` as follows:
```console
/usr/sbin/genl
/usr/share/teams/libvulkan.so
/usr/share/code/libvulkan.so.1
/usr/share/atom/libvulkan.so
/usr/lib/libreoffice/program/libvclplug_genlo.so
/usr/lib/x86_64-linux-gnu/libvulkan.so.1.3.204
/usr/lib/x86_64-linux-gnu/libnl-genl-3.so.200.26.0
```

Now we pass this list to the python utility.
```console
$ python dlsummary.py --input input_files.txt --raw-output raw.txt --csv-output results.txt 
INFO:root:Processing input file list: input_files.txt
INFO:root:# available digests: 7
INFO:root:Completed Writing: results.txt
```

The results are written to the `results.txt`. Note only the results with non-zero findings are reported.
```console
File,dlopenCount,dlopenWithStaticString,dlsymCount,dlsymWithStaticString,dlvsymCount,dlvsymWithStaticString,dlmopenCount,dlmopenWithStaticString,dlsymMapped,dlsymWithConstHandle,dlvsymMapped,dlvsymWithConstHandle
/usr/sbin/genl,2,0,1,0,0,0,0,0,1,0,0,0
/usr/share/teams/libvulkan.so,6,0,16,9,0,0,0,0,15,0,0,0
/usr/share/code/libvulkan.so.1,6,0,16,10,0,0,0,0,16,0,0,0
/usr/share/atom/libvulkan.so,6,0,16,9,0,0,0,0,15,0,0,0
/usr/lib/x86_64-linux-gnu/libvulkan.so.1.3.204,6,0,17,10,0,0,0,0,10,0,0,0
```

The full output is dumped to the `raw.txt` file in this case.

## Running on system-wide ELF files
For this use the `runfulltest.sh` script (simply execute it). It will scan for ELF files in locations under `/usr/*` and then use the above utility to run against this list.

## Deep Dive

### 1. Identifying dlopen, dlsym, dlvsym, and dlmopen calls.
The tool makes use of the dyninst call graph and finds determines calls to the abovementioned functions. This is done by finding all calls locations in the 
code and then checking for the call edge to a function in the PLT with 
the proper name.

### 2. Argument tracking for identified calls
For each of the calls that we identify, we try to figure out some of the key arguments. More specifically, in case of `dlopen` and `dlmopen` the idea is to figure out the library path/name string. Similarly, for `dlsym` and `dlvsym`, the symbol string is of particular interest. This is also an area of future work.

Currently we are only able to figure out any static string literals (being read from `.rodata`) while forming the arguments. This is not necessarily same as saying "a static string was passed" and is actually a larger set containing static string args and more.

The approach goes as follows:
 - We figure out the argument register `reg` that is supposed to contain the argument of interest as per the position in the call.
 - Going back from the `call` instruction, we locate the last assignment made to `reg` and run backward slicing (with stack analysis enabled) on it. 
 - The backward slicing returns a graph of assignments. We traverse this graph and find any string reads happening from the `.rodata` section.

### 3. Mapping dlsym handles to dlopen calls
It is worth noting that currently we are only able to map calls that are intra-procedural i.e. dlopen and related dlsym calls happen from within the same function. This leaves a large number of wrapper based calling patterns unsupported.

The mapping logic goes as follows:
 - We start from the basic block that ends in a call to `dlopen` and take out the block that is reachable via the `CALL_FALLTHROUGH` edge. This block is the code that is going to be executed after the `dlopen` call returns.
 - Starting from the fallthrough block, we traverse and prepare a set `S` of basic blocks that are reachable without calling another function or returning from the containing function.
 - We repeat the above procedure and associate each `dlopen` call with a corresponding set `S`.
 - Now, we go through `dlsym` calls, one by one, and backward slice from the last assignment to the register containing the handle. In the backward slice, we try to find reads from the `return` register i.e. `%rax`. The idea is to find if the read instruction belongs to the set `S` for any of the dlopens. If so, we have found the mapping!

### 4. dlsym calls with constant handles
Here again, the idea is similar to (2) and we backward slice from the argument register containing the handle to check if we are able to evaluate it as a constant.

## Future Work
 - The call identification code makes use of parseAPI instead of dyninstAPI. This limits our ability to handle stripped binaries. We need to migrate the tool to use dyninstAPI instead.
 - Many applications are found to be making use of wrappers for dlopen/dlsym calls. The current analysis methodology will resolve the libnames and symbols to function parameters and will not detect string literals which the parameters might have resolved to upon further backward slicing.
 - String based optimisations are quite common. The behaviour of strcpy, strcat, strcmp, etc. needs to be studied and common operations need to be supported to improve argument tracking.

