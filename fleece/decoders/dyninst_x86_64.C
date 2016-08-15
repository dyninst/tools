
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

#include "InstructionDecoder.h"
#include "Mystring.h"
#include <string>
#include <iomanip>

using namespace Dyninst;
using namespace InstructionAPI;

/*
 * This function will instruct the caller to skip operands which are known to
 * be implicit in Intel syntax but explicit in Dyninst output.
 */
bool skipOperand(std::string& opcode, std::string& operand, int pos) {

   // Each operand has a 0-indexed position passed in with it. This list of
   // which opcodes and position are implicit was created by examining the
   // fuzzed output of fleece and seeing which opcodes has which positions
   // written only explicitly by Dyninst and not in Intel syntax.
   if (opcode == "ret far" && pos == 0)
      return true;

   if (opcode == "ret" && pos == 0)
      return true;

   if ((opcode == "pop" || opcode == "push") && pos == 1)
      return true;

   if ((opcode == "lodsd" || opcode == "lodsb" || opcode == "lodsw") && pos == 0)
      return true;

   if ((opcode == "scasb" || opcode == "scasd" || opcode == "scasw") && pos == 0)
      return true;

   if ((opcode == "stosd" || opcode == "stosb" || opcode == "stosw") && pos == 1)
      return true;

   if ((opcode == "mul"  || opcode == "div" || 
        opcode == "idiv") &&
       (pos == 0 || pos == 1))
      return true;

   if (opcode == "imul" && ((pos == 0 && operand == "ax") ||
                            (pos == 1 && operand == "al") ||
                            (pos == 0 && operand == "rdx") ||
                            (pos == 1 && operand == "rax")))
      return true;
   
   if ((opcode == "loop" || opcode == "loope" || opcode == "loopne") &&
        pos == 1)
      return true;

   if ((opcode == "jcxz/jec") &&
        pos == 1)
      return true;

   // This list should be moved out eventually, but for now, these are all
   // instructions that have no explicit operands in Intel syntax.

   if (opcode == "wrmsr" || opcode == "cdq"     || opcode == "outsb"  ||
       opcode == "outsd" || opcode == "outsw"   || opcode == "popf"   ||
       opcode == "popfd" || opcode == "pushfd"  || opcode == "insd"   ||
       opcode == "insb"  || opcode == "syscall" || opcode == "sysret" ||
       opcode == "cwde"  || opcode == "cbw"     || opcode == "pushf"  ||
       opcode == "insw"  || opcode == "cwd") {
      return true;
   }

   return false;
}

std::string reformatOperand(std::string& opcode, std::string& operand, int pos) {

   // If this was an lea instruction, add the brackets around it.
   if (opcode == "lea" && pos == 1)
      operand = std::string("[") + operand + std::string("]");

   // A fix for the "+rip+" substring: add the two values on the sides.
   size_t startIndex = operand.find("+rip+");
   if (startIndex != std::string::npos) {

      // Identify the start of both hex strings.
      size_t start1 = 2;
      size_t end1 = startIndex;
      size_t start2 = startIndex + 7;
      size_t end2 = operand.length();

      // Convert the left value into an unsigned long from hex.
      unsigned long val1;
      std::stringstream stream1;
      stream1 << std::hex << operand.substr(start1, end1 - start1);
      stream1 >> val1;

      // Convert the right value into an unsigned long from hex.
      unsigned long val2;
      std::stringstream stream2;
      stream2 << std::hex << operand.substr(start2 , end2 - start2);
      stream2 >> val2;

      // Now, we want to sum the two and write it to a hex string with 0x in
      // front of it. Since the "+rip+" substring always just has two hex
      // values, we can return.
      std::stringstream stream3;
      stream3 << std::hex << val1 + val2;
      std::string str;
      stream3 >> str;
      return std::string("0x") + str;
   }

   // Rearrange operands of the form [hex+reg] to [reg+hex], since others tend
   // to do it this way.
   startIndex = operand.find("+r");
   size_t hexIndex = operand.find("0x");
   if (startIndex != std::string::npos && hexIndex < startIndex) {
      size_t regStart = startIndex + 1;
      size_t regEnd = operand.length();

      if (operand.at(operand.length() - 1) == ']') {
         regEnd--;
      }

      size_t hexStart = 0;
      size_t hexEnd = startIndex - 1;

      if (operand.at(0) == '[') {
         hexStart++;
      }

      std::string str = operand.substr(hexStart, hexEnd);
      operand.replace(hexStart, hexEnd, operand.substr(regStart, regEnd - regStart));
      operand.replace(hexStart + regEnd - regStart + 1, regEnd - regStart, str);

   }

   startIndex = operand.find("+0x0]");
   if (startIndex != std::string::npos) {
      operand.replace(startIndex, 4, "");
   }

   // Now we do processing for all hex arithmetic. Dyninst always puts out
   // positive numbers (hence the" +" in "+0x" below).
   startIndex = operand.find("+0x");
   if (startIndex != std::string::npos) {

      // We need to skip over the "+0x" characters to get to the hex.
      size_t intIndex = startIndex + 3;

      // We should be in dereferencing with hex arithmetic, so we will look for
      // the closing brace as a sign of the end of the hex string.
      size_t endIndex = operand.find("]", startIndex);
      if (endIndex == std::string::npos) {
         //cout << "WARNING: could not find end of hex string (looking for \']\')!\n";
         //std::cout << "\t" << operand << std::endl;
         endIndex = operand.length() - 1;
      }

      // Now, convert the string to an unsigned value and a signed counterpart.
      unsigned long val;
      std::stringstream stream;
      stream << std::hex << operand.substr(intIndex , endIndex - intIndex);
      stream >> val;
      long signedVal;

      // Depending of the length of the hex string, we need to pick the correct
      // size for the value, then cast to the signed version appropriately.
      if (endIndex - intIndex <= 2) {
         signedVal = (char)val;
      } else if (endIndex - intIndex <= 4) {
         signedVal = (short)val;
      } else if (endIndex - intIndex <= 8) {
         signedVal = (int)val;
      } else if (endIndex - intIndex <= 16) {
         signedVal = (long)val;
      } else {
         signedVal = -1;
         std::cout << "Could not match hex size to type size (not 1, 2, 4 or 8 bytes)!" << std::endl;
         std::cout << "\t" << endIndex << " - " << intIndex << std::endl;
      }

      // If our signed value was negative, we need to replace the "+" with a
      // "-".
      if (signedVal < 0) {
         std::string str;
         std::stringstream stream2;
         stream2 << std::hex << -1 * signedVal;
         stream2 >> str;

         // Here, we overwrite the old, unsigned value and overwrite the
         // arithmetic operator from "+" to "-". Note that we dont overwrite
         // the value in the positive case since the value should not have
         // changed.
         operand.replace(intIndex, endIndex - intIndex, str);
         operand.replace(startIndex, 1, "-");
      }
      
   }
   
   return operand;
}

/*
 * Right now, this is just a collection of translations to make opcodes match.
 */
std::string reformatOpcode(std::string& opcode) {
   if (opcode == "wait")
      return std::string("fwait");

   if (opcode == "shl/sal")
      return std::string("shl");

   if (opcode == "ret near" || opcode == "ret far")
      return std::string("ret");

   if (opcode == "loopn")
      return std::string("loopne");

   if (opcode == "int 3")
      return std::string("int3");

   if (opcode == "cmovng")
      return std::string("cmovle");

   if (opcode == "cmovpo")
      return std::string("cmovnp");
   
   if (opcode == "cmovnae")
      return std::string("cmovb");

   if (opcode == "cmovpe")
      return std::string("cmovp");

   if (opcode == "cmovnge")
      return std::string("cmovl");

   if (opcode == "cmove")
      return std::string("cmovz");

   if (opcode == "movhps/movlhps")
      return std::string("movhps");

   if (opcode == "movlps/movhlps")
      return std::string("movlps");
   
   return opcode;
}

std::ostream& operator<<(std::ostream& s, const Instruction::Ptr p) {
   vector<Operand> operands;
   p->getOperands(operands);

   // Read in the Operation from the instruction
   Operation operation = p->getOperation();
   std::string op = operation.format();

   // Reformat the opcode and remove any spaces in it.
   op = reformatOpcode(op);
   s << op;

   // Begin reformatting each operand.
   bool firstOperand = true;
   for (size_t i = 0; i < operands.size(); i++) {
      std::string result = operands[i].format(Arch_x86_64);

      // Erase spaces and put everything in lower case.
      result.erase(remove(result.begin(), result.end(), ' '), result.end());
      transform(result.begin(), result.end(), result.begin(), ::tolower);

      // These substrings are always implicit, so remove them.
      removeAtSubStr(result, "es*10+", 6);
      removeAtSubStr(result, "ds*10+", 6);

      // Check if the operand needs to be skipped for Intel syntax.
      if (skipOperand(op, result, i)) {
         continue;
      }

      // If there are any hex values, put 0x in front of them.
      prepend0x(result);

      // Check to see if we need a comma (this will skip the first operand).
      if (!firstOperand) {
         s << ",";
      } else {
         firstOperand = false;
      }

      // Output a reformatted version of this operand.
      s << " " << reformatOperand(op, result, i);
   }
   return s;
}

void dynReformat(Instruction::Ptr p, char* buf, int bufLen) {
   std::ostringstream instStream;
   instStream << p;
   std::string str = instStream.str();   
   strncpy(buf, str.c_str(), bufLen);
   buf[bufLen - 1] = 0;
}

void dyninst_x86_64_norm(char* buf, int bufLen) {
   char* cur = buf;
   char* replace = buf;
   bool inSpace = true;
   while (*cur) {
      if (isspace(*cur)) {
         if (!inSpace) {
            inSpace = true;
            *replace = ' ';
            replace++;
         }
      } else {
         inSpace = false;
         if (isupper(*cur)) {
            *replace = *cur + 32 ;
         } else {
            *replace = *cur;
         }
         replace++;
      }
      cur++;
   }
   *replace = *cur;
 
}

int dyninst_x86_64_decode(char* inst, int nBytes, char* buf, int bufLen) {
   
   InstructionDecoder d(inst, nBytes, Arch_x86_64);
   Instruction::Ptr p = d.decode();
   strncpy(buf, p->format().c_str(), bufLen);
   return 0;
}
