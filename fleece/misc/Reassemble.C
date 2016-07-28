#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <ios>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <fstream>
#include <string.h>

#define BUFFER_SIZE 1024
#define TMP_FILENAME "tmp_asm_file_2465254685.s"

char getHexValue(char h);
char reassemble(char* bytes, int nBytes, char* str, FILE* tmp, const char* tmpname);
void writeStrToFile(const char* file, long offset, char* str);

int main(int argc, char** argv) {

   if (argc < 2) {
      std::cout << "Error: no input file\n";
      return 0;
   }

   FILE* asmFile = fopen(TMP_FILENAME, "w");

   assert(fwrite(".global main\n\nmain:\n\t", 1, 21, asmFile) == 21);
   long asmOffset = ftell(asmFile);
   assert(fclose(asmFile) == 0);

   char* str1  = (char*)malloc(BUFFER_SIZE);
   char* str2  = (char*)malloc(BUFFER_SIZE);
   char* bytes = (char*)malloc(BUFFER_SIZE);

   assert(str1 != NULL && str2 != NULL && bytes != NULL);

   std::string line;
   std::ifstream infile(argv[1]);
   std::getline(infile, line);
   std::cout << line << "\n";

   int nFirstDiff  = 0;
   int nFirstSame  = 0;
   int nFirstError = 0;
   
   int nSecondDiff  = 0;
   int nSecondSame  = 0;
   int nSecondError = 0;

   while (std::getline(infile, line)) {

      char* s1 = str1;
      char* s2 = str2;

      const char* cur = line.c_str();
      while (*cur && *cur != ';' && s1 < str1 + BUFFER_SIZE - 1) {
         *s1 = *cur;
         cur++;
         s1++;
      }
      *s1 = 0;

      if (*cur == ';') {
         cur += 2;
      }

      while (*cur && *cur != ';' && s2 < str2 + BUFFER_SIZE - 1) {
         *s2 = *cur;
         cur++;
         s2++;
      }
      *s2 = 0;

      char* bytes = (char*)malloc(BUFFER_SIZE);
      const char* byteStr = cur;
      int curByte = 0;
      while (*byteStr && curByte < BUFFER_SIZE) {
         bytes[curByte] = getHexValue(*cur) << 4 + getHexValue(*(cur + 1));
         byteStr += 3;
      }

      int nBytes = curByte;
            
      std::cout << str1 << "; " << str2 << cur << "; ";
      
      writeStrToFile(TMP_FILENAME, asmOffset, str1);
      char result = reassemble(bytes, nBytes, str1, asmFile, TMP_FILENAME);
      if (result == 'S') {
         nFirstSame++;
      } else if (result == 'D') {
         nFirstDiff++;
      } else {
         nFirstError++;
      }
      std::cout << result;
      
      writeStrToFile(TMP_FILENAME, asmOffset, str2);
      result = reassemble(bytes, nBytes, str2, asmFile, TMP_FILENAME);
      if (result == 'S') {
         nSecondSame++;
      } else if (result == 'D') {
         nSecondDiff++;
      } else {
         nSecondError++;
      }
      std::cout << result << "\n";

   }

   free(bytes);
   infile.close();

   std::cout << "First Same:      " << nFirstSame  << "\n";
   std::cout << "First Different: " << nFirstDiff  << "\n";
   std::cout << "First Error:     " << nFirstError << "\n\n";

   std::cout << "Second Same:      " << nSecondSame  << "\n";
   std::cout << "Second Different: " << nSecondDiff  << "\n";
   std::cout << "Second Error:     " << nSecondError << "\n";
}

void writeStrToFile(const char* filename, long offset, char* str) {
   FILE* file = fopen(filename, "w+");
   
   assert(file != NULL);
   assert(fseek(file, offset, SEEK_SET) != -1);
   assert(ftruncate(fileno(file), offset) == 0);
   assert(fprintf(file, "%s\n", str) == strlen(str) + 1);
   assert(fclose(file) == 0);
}

char getHexValue(char h) {
   if (h >= '0' && h <= '9') {
      return h - 0;
   }

   if (h >= 'A' && h <= 'F') {
      return h + 10 - 'A';
   }

   return h + 10 - 'a';
}

char reassemble(char* bytes, int nBytes, char* str, FILE* tmp, const char* tmpname) {

   char* buf = (char*)malloc(BUFFER_SIZE);
   assert(buf != NULL);

   snprintf(buf, BUFFER_SIZE, "as -o %s.o %s 2>as.out", tmpname, tmpname);
   int rc = system(buf);

   if (rc != 0) {
      free(buf);
      return 'E';
   }

   snprintf(buf, BUFFER_SIZE, "objdump -d %s.o > %s.tmp", tmpname, tmpname);
   system(buf);

   snprintf(buf, BUFFER_SIZE, "%s.tmp", tmpname);
   FILE* bytef = fopen(buf, "r+");
   assert(bytef != NULL);

   int flen = fread(buf, 1, BUFFER_SIZE, bytef);
   assert(flen > 0);

   assert(fclose(bytef) == 0);

   char* cur = buf;
   char* end = buf + flen;

   int tabCount = 0;
   while (cur < end && tabCount < 3) {
      if (*cur == '\t') {
         tabCount++;
      }
      cur++;
   }

   int curByte = 0;
   while (*cur != '\t' && cur < end - 1 && curByte < nBytes) {
      char c = (getHexValue(*cur) << 4) + getHexValue(*(cur + 1));
      if (c != bytes[curByte]) {
         free(buf);
         return 'D';
      }
      curByte++;
      cur += 2;
   }

   free(buf);
 
   if (*cur == '\t' || cur >= end - 1) {
      return 'D';
   }

   return 'S';
}

