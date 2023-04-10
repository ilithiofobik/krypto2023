#include <stdio.h>

#include "rand_gen.h"

int main() {
   ranctx y = ranctx { 1, 2, 3, 4 };
   raninit(&y, 5);
   u4 z = ranval(&y);

   printf("z = %d\n", z);
   return 0;
}