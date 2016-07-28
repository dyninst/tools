
#include <iostream>
#include <bitset>

int main(int argc, char** argv) {
   std::cout << "universe = vanilla\n";
   std::cout << "should_transfer_files = YES\n";
   std::cout << "executable = exec_fleece.sh\n";
   std::cout << "notification = Never\n";
   std::cout << "request_memory = 1 GB\n";
   std::cout << "Requirements = ( ( OpSysAndVer == \"RedHat6\") ) || ( ( OpSysAndVer == \"SL6\") )\n";
   
   for (int i = 0; i < 256; i++) {
      std::cout << "transfer_input_files = exec_fleece.sh,libstdc++.so.6,libcommon.so.9.1,libbfd-2.26.51.20160204.so,libLLVM-3.9.0svn.so,libopcodes.so,libinstructionAPI.so,libLLVM-3.9svn.so,libxed.so,libinstructionAPI.so.9.1,libLTO.so,fleece,libinstructionAPI.so.9.1.0,libopcodes-2.26.51.20160204.so\n";
      std::cout << "output = out." << i << "\n";
      std::cout << "error = error." << i << "\n";
      std::cout << "log = log." << i << "\n";
      std::cout << "arguments = \"-arch=aarch64 -decoders=llvm,gnu -rand -n=16777216 -len=4 -norm -mask=nnnnnnnnnnnnnnnnnnnnnnnn";
      std::bitset<8> x(i);
      std::cout << x << "\"\n";
      std::cout << "queue\n";
   }
}
