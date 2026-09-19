/* A compute-bound loop of integer divisions by constants (independent, so it is
   throughput- not latency-bound). LLVM/gcc strength-reduce each `/ const` to a magic
   multiply + shift, issuing several per cycle; a back end that emits real hardware
   `idiv` pays ~20-40 cycles each and cannot pipeline them. This is the clearest gap
   between sic and the LLVM toolchains that is NOT auto-vectorization. Prints the sum. */
#include <stdio.h>

#define N 200000000

int main(void) {
    long sum = 0;
    for (long i = 1; i < N; i++)
        sum += i / 7 + i / 13 + i / 143 + i / 1001;
    printf("%ld\n", sum);
    return 0;
}
