
#include "Mask.h"

char* getPartialMask(const char* strMask, int maskLen, char symbol) {
   char* partMask = (char*)malloc(maskLen);
   assert(partMask != NULL);
   bzero(partMask, maskLen);
   

   for (int i = 0; i < 8 * maskLen && strMask[i]; i++) {
      if (strMask[i] == symbol) {
         setBufferBit(partMask, i, 1);
      }
   }

   return partMask;
}

Mask::Mask(const char* strMask) {
   assert(strMask != NULL && *strMask && "NULL string mask!");

   maskLen = (strlen(strMask) + 7) / 8;
   setMask = getPartialMask(strMask, maskLen, MASK_SYMBOL_SET_BIT);
   clrMask = getPartialMask(strMask, maskLen, MASK_SYMBOL_CLR_BIT);
   incMask = getPartialMask(strMask, maskLen, MASK_SYMBOL_INC_BIT);
   
   incVal = (char*)malloc(maskLen);
   assert(incVal != NULL);
   bzero(incVal, maskLen);
}

Mask::~Mask() {
   free(setMask);
   free(clrMask);
   free(incMask);
   free(incVal);
}

void Mask::increment(void) {
   char* cur = incVal + maskLen - 1;
   while (cur >= incVal && !(++(*cur))) {
      cur--;
   }
}

void Mask::apply(char* buf, int bufLen) {
   assert(bufLen >= maskLen);
   
   // Handle setting and clearing.
   for (int i = 0; i < maskLen; i++) {
      buf[i] |= setMask[i];
      buf[i] &= ~clrMask[i];
   }

   // Handle the incremented value.
   int valBit = 8 * maskLen - 1;
   for (int i = 8 * maskLen - 1; i >= 0; i--) {
      if (getBufferBit(incMask, i)) {
         setBufferBit(buf, i, getBufferBit(incVal, valBit));
         valBit--;
      }
   }
}
