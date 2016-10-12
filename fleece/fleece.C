
/*
 * See fleece/COPYRIGHT for copyright information.
 *
 * This file is a part of Fleece.
 *
 * Fleece is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License, or (at your option)
 * any later version.
 *  
 * This software is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, see www.gnu.org/licenses
*/

#include <fstream>
#include <iomanip>
#include <iostream>
#include <ios>
#include <map>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include "Alias.h"
#include "Decoder.h"
#include "Info.h"
#include "Mask.h"
#include "MappedInst.h"
#include "Options.h"
#include "ReportingContext.h"
#include "StringUtils.h"

#define DECODED_BUFFER_LEN 256
#define FLUSH_FREQ 100
#define DIR_ACCESS_PERMS S_IRUSR | S_IWUSR | S_IXUSR

int main(int argc, char** argv) {

    /***********************************************************************/
    /*                     PARSING COMMAND LINE ARGS                       */
    /***********************************************************************/

    Options::parse(argc, argv);

    // The user selected the "-help" option, so print help and exit.
    if (Options::get("-help") || Options::get("-h")) {
        Info::printOptions();
        exit(0);
    }

    // The user selected the "-version" option, so print the version and exit.
    if (Options::get("-version") != NULL) {
        Info::printVersion();
        exit(0);
    }
   
    // Should output from decoders be normalized before use?
    bool norm     = (Options::get("-norm")  != NULL);

    // Should the input method be random bytes with an (optional) mask?
    bool random   = (Options::get("-rand")  != NULL);

    // Should the raw bytes of an insn be printed right before decoding?
    bool showInsn = (Options::get("-bytes") != NULL);

    // Should the program read input from stdio?
    bool pipe     = (Options::get("-pipe")  != NULL);

    // Seed the random number generator with the time or a provided seed.
    const char* strSeed = Options::get("-seed=");
    if (strSeed == NULL) {
        srand(time(NULL));
    } else {
        srand(strtoul(strSeed, NULL, 10));
    }

    // Determine the instruction length. The default value is 15 bytes.
    unsigned long insnLen = 15;
    const char* strInsnLen = Options::get("-len=");
    if (strInsnLen != NULL) {
        insnLen = strtoul(strInsnLen, NULL, 10);
    }

    // Check which architecture was specified.
    const char* archStr = Options::get("-arch=");
    if (!archStr) {
        std::cerr << "FLEECE FATAL: Must specify architecture!\n";
        exit(1);
    }

    /* Initialize our decoders */
    Decoder::initAllDecoders();
    // Initialize the architecture with the command line name.
    Architecture::init(archStr);

    // Get a list of all decoders that should be used, from the comma separated
    // list of names on the command line
    const char* decStr = Options::get("-decoders=");

    // The Decoder class has a static method to match architecture and decoder
    // strings.
    std::vector<Decoder> decoders = Decoder::getDecoders(archStr, decStr);
    size_t decCount = decoders.size();
   
    // If there were no valid decoders with the architecture, print all decoder
    // and architecture pairs and continue.
    if (decCount == 0) {
        std::cout << "FLEECE FATAL: No decoders for this architecture.\n"; 
        std::cout << "Valid options are:\n";
        Decoder::printAllNames();
        exit(0);
    }

    // Verify that the user has provided a byte source or specified a number of
    // random instruction.
    unsigned long nRuns = 0;
    const char* strRuns = Options::get("-n=");
    if (strRuns == NULL && !pipe) {
        std::cout << "FLEECE FATAL: Need \"-n=<# of insns>\" or \"-pipe\"\n";
        exit(0);
    } else if (!pipe) {
        nRuns = strtoul(strRuns, NULL, 10);
    }

    // Get the specified output file
    const char* outputDir = Options::get("-o=");
    if (outputDir == NULL) {
        outputDir = "fleece_results";
    }
    int rc = mkdir(outputDir, DIR_ACCESS_PERMS);
    if (rc != 0) {
        if (errno != EEXIST) {
            std::cerr << "FLEECE FATAL: Cannot create output directory:"
                    << outputDir << "\n";
            exit(-1);
        }
    }

   // If the user passes in a mask value, read that in now.
   const char* strMask = Options::get("-mask=");
   bool hasMask = (strMask != NULL);
   Mask* mask = NULL;

   // The mask constructor will do all of the necessary string parsing.
   if (hasMask) {
      mask = new Mask(strMask);
   }

   /************************************************************************/
   /*                   END OF COMMAND LINE ARG PARSING                    */
   /************************************************************************/

   // We'll be needing these, trust me (loop vars).
   unsigned long i, j;

   // Allocate a starting instruction and a temporary instruction to be used
   // during decoding.
   char* baseInsn = (char*)malloc(insnLen);
   char* tempInsn = (char*)malloc(insnLen);

   assert(baseInsn != NULL && tempInsn != NULL);

   // Allocate buffers for the output from each of the decoders.
   char** decBufs = (char**)malloc(decCount * sizeof(char*));
   assert(decBufs != NULL && "Could not allocate decoder buffers!");

   for (size_t i = 0; i < decCount; i++) {
      decBufs[i] = (char*)malloc(DECODED_BUFFER_LEN);
      assert(decBufs[i] != NULL && "Could not allocate decoder buffer!");
   }

    // Instantiate a reporting context with the chosen output file.
    ReportingContext* repContext = new ReportingContext(outputDir, FLUSH_FREQ);
    assert(repContext != NULL && "Reporting context should not be null!");
    for (size_t i = 0; i < decCount; i++) { 
        repContext->addDecoder(decoders[i].getName());
        char dirBuf[REPORT_FILENAME_BUF_LEN];
        snprintf(dirBuf, REPORT_FILENAME_BUF_LEN, "%s/%s", outputDir, \
                decoders[i].getName());
        int rc = mkdir(dirBuf, DIR_ACCESS_PERMS);
        if (rc != 0) {
            if (errno != EEXIST) {
                std::cerr << "FLEECE FATAL: Cannot create output directory:"
                        << dirBuf << "\n";
                exit(-1);
            }
        }
    }

   // Create a map as a counter for all of the seen formats when queuing new
   // instructions.
   std::map<char*, int, StringUtils::str_cmp> seenMap;
   std::queue<char*> remainingInsns;

    if (!random && !pipe) {
        for (i = 0; i < nRuns; i++) {
            // Create an initial random instructions for the queue.
            randomizeBuffer(baseInsn, insnLen);

            // Push the random instruction onto the queue.
            remainingInsns.push(baseInsn);
            baseInsn = (char*)malloc(insnLen);
        }
    }

   // Record the time reported and report stats to std::cerr regularly.
   unsigned long lastTime = 0;

   // Output a header to std::cerr.
   std::cerr << "decoded, queued, reports, matches, suppressed\n";

   // The current instruction in the loop.
   char* curInsn = NULL;

   if (random || pipe) {
      curInsn = (char*)malloc(insnLen);
   }

   uint64_t totalDisasmTime = 0;
   uint64_t totalMapTime = 0;
   struct timespec startTime, endTime;

   i = 0;
   while (pipe || (!random && !remainingInsns.empty()) 
           || (random && i < nRuns)) {

      i++;

      // If it has been 10 seconds, output a new line to std::cerr with data.
      unsigned long newTime = time(NULL);

      if (newTime >= lastTime + 10) {
         lastTime = newTime;
         
         // Count the total number of instructions decoded.
         unsigned long nDecoded = 0;
         for (j = 0; j < decCount; j++) {
            nDecoded += decoders[j].getTotalDecodedInsns();
         }

         // Output instructions decoded and summary of reporting done.
         std::cerr << nDecoded << ", " << remainingInsns.size() << ", ";
         repContext->printSummary(stderr);
         std::cerr << "Disasm Time: " << totalDisasmTime / 1000000000 << "\n";
         std::cerr << "Map Time: " << totalMapTime / 1000000000 << "\n";
      }

      bool pipeEmpty = false;

      // Get the next instruction.
      if (random) {

         // Fill the buffer then apply the mask.
         randomizeBuffer(curInsn, insnLen);
         if (hasMask) {
            mask->apply(curInsn, insnLen);
            mask->increment();
         }
      } else if (pipe) {
         
         // Read from stdin if we're in pipe mode.
         pipeEmpty = (getStdinBytes(curInsn, insnLen) == -1);
         if (pipeEmpty) {
            break;
         }
      } else {
         
         // If insns are not random, take them from the queue.
         curInsn = remainingInsns.front();
         remainingInsns.pop();
      }

      // If the user selected to see the instruction before decode, print it
      // now.
      if (showInsn) {
         for (j = 0; j < insnLen; j++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                << (unsigned int)(unsigned char)curInsn[j] << " ";
         }
         std::cout << "\n" << std::dec;
      }
      
      clock_gettime(CLOCK_MONOTONIC, &startTime);
      // Use each decoder to decode the instruction.
      for (j = 0; j < decCount; j++) {
         bcopy(curInsn, tempInsn, insnLen);

         int retval = decoders[j].decode(
            tempInsn, 
            insnLen, 
            decBufs[j], 
            DECODED_BUFFER_LEN
         );

         // We want to make sure that all decoders were at least able to come
         // up with some kind of decoding, otherwise we'll fill it with a
         // defaul bad value to be used later as an error indicator.
         if (retval != 0) {
            strcpy(decBufs[j], "decoding_error");
         }

         if (norm) {
            decoders[j].normalize(decBufs[j], DECODED_BUFFER_LEN);
         }
         
      }

      // Process the resulting decoding and report it if necessary
      repContext->processDecodings(
         (const char**)decBufs, 
         decCount, 
         curInsn, 
         insnLen
      );
      clock_gettime(CLOCK_MONOTONIC, &endTime);

      totalDisasmTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                      (endTime.tv_nsec - startTime.tv_nsec);
      

      clock_gettime(CLOCK_MONOTONIC, &startTime);
      if (!random && !pipe) {

         // If the input is non-random, we need to add to the queue now.
         MappedInst* mInsn;


         for (size_t j = 0; j < decCount; j++) {
            
            // Each decoder maps the instruction and each instruction uses its
            // map to try to find interesting instructions and add them to the
            // queue.
            mInsn = new MappedInst(curInsn, insnLen, &decoders[j], norm);
            mInsn->queueNewInsns(&remainingInsns, &seenMap);
            delete mInsn;
         }
      }

      // If the instruction was from the queue, it was malloced at somepoint
      // and we need to free it.
      if (!random) {
         free(curInsn);
      }
      clock_gettime(CLOCK_MONOTONIC, &endTime);

      totalMapTime += 1000000000 * (endTime.tv_sec  - startTime.tv_sec ) +
                                   (endTime.tv_nsec - startTime.tv_nsec);
      //random = true;
      //nRuns = 0;
   }

   // Print a summary at the end of execution.
   repContext->printSummary(stdout);

   // Report the total number of decoded instructions.
   unsigned long totalDecInsns = 0;
   for (size_t i = 0; i < decCount; i++) {
      totalDecInsns += decoders[i].getTotalDecodedInsns();
   }

   std::cout << "Total instructions decoded: " << totalDecInsns << "\n";

   delete repContext;

   if (hasMask) {
      delete mask;
   }

   for (size_t i = 0; i < decCount; i++) {
      free(decBufs[i]);
   }
   free(decBufs); 

   if (!random && !pipe) {
      free(baseInsn);
   }
   free(tempInsn);
   
   Architecture::destroy();
   Alias::destroy();
   Options::destroy();
   Decoder::destroyAllDecoders();
   return 0;
}
