#ifndef LAB1_RAND_GEN_H
#define LAB1_RAND_GEN_H

#include <cstdint>

typedef uint32_t u4;
typedef struct ranctx { u4 a; u4 b; u4 c; u4 d; } ranctx;

u4 ranval(ranctx *x);
void raninit(ranctx* x, u4 seed);

#endif  // LAB1_RAND_GEN_H