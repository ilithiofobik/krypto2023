#include "rand_gen.h"

#define rot32(x,k) (((x)<<(k))|((x)>>(32-(k))))

u4 ranval(ranctx *x) {
    u4 e = x->a - rot32(x->b, 27);
    x->a = x->b ^ rot32(x->c, 17);
    x->b = x->c + x->d;
    x->c = x->d + e;
    x->d = e + x->a;
    return x->d;
}

void raninit(ranctx* x, u4 seed) {
    u4 i;
    x->a = 0xf1ea5eed;
    x->b = x->c = x->d = seed;
    for (i=0; i<20; ++i) {
        (void)ranval(x);
    }
}