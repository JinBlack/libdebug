#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main(int argc, char ** argv){
    uint64_t i0,i1,i2;
    i0 = i1 = i2 = 0;

    while(1){
        i0++;
        if (i0 == 0){
            i1++;
        }
        if (i1 == 0){
            i2++;
        }
        if(i0 == 0 && i1 >= 0x2){
            break;
        }
        printf("%lu %lu %ld", i0, i1, i2);
    }
}