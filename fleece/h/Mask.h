#ifndef _MASK_H_
#define _MASK_H_

#include "Mystring.h"
#include <iostream>
#include <iomanip>

#define MASK_SYMBOL_SET_BIT '1'
#define MASK_SYMBOL_CLR_BIT '0'
#define MASK_SYMBOL_INC_BIT 'n'

class Mask {

public:

   Mask(char* strMask);

   ~Mask();

   void increment(void);

   void apply(char* buf, int bufLen);

private:

   char* setMask;
   char* clrMask;
   char* incMask;
   char* incVal;

   int maskLen;

};

#endif /* _MASK_H_ */
