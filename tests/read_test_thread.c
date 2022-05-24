#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define MAPPED_ADDRESS_1 0x1aabbcc1000
#define MAPPED_ADDRESS_2 0x2aabbcc2000
#define MAPPED_ADDRESS_3 0x3aabbcc3000

#define MAP_SIZE 0x1000
#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)


void *fun1(void* address){
    printf("address %#lx\n", address);
    printf("tid: %d\n",  gettid());
    char *p = mmap((void *)address, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (p == MAP_FAILED)
        handle_error("mmap");
    for (int i=0; i < MAP_SIZE; i++){
        p[i] = 0xff - (i%0x100);
    }

    while(1){
    __asm__("movq $0x11, %rax \n\t"
            "movq $0x1122334455667788, %rbx \n\t"
            "movq $0x2233445566778899, %rcx \n\t"
            "movq $0x33445566778899aa, %rdx \n\t"
            "movq $0x445566778899aabb, %rdi \n\t"
            "movq $0x5566778899aabbcc, %rsi \n\t"
            "movq $0x66778899aabbccdd, %rsp \n\t"
            "movq $0x778899aabbccddee, %rbp \n\t"
            "movq $0x8899aabbccddeeff, %r8  \n\t"
            "movq $0xffeeddccbbaa9988, %r9  \n\t"
            "movq $0xeeddccbbaa998877, %r10 \n\t"
            "movq $0xddccbbaa99887766, %r11 \n\t"
            "movq $0xccbbaa9988776655, %r12 \n\t"
            "movq $0xbbaa998877665544, %r13 \n\t"
            "movq $0xaa99887766554433, %r14 \n\t"
            "movq $0x9988776655443322, %r15 \n\t"
            );
    }
}

void *fun2(void* address){
    printf("address %#lx\n", address);
    printf("tid: %d\n",  gettid());
    char *p = mmap((void *)address, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (p == MAP_FAILED)
        handle_error("mmap");
    for (int i=0; i < MAP_SIZE; i++){
        p[i] = 0xff - (i%0x100);
    }

    while(1){
    __asm__("movq $0x22, %rax \n\t"
            "movq $0x1122334455667788, %rbx \n\t"
            "movq $0x2233445566778899, %rcx \n\t"
            "movq $0x33445566778899aa, %rdx \n\t"
            "movq $0x445566778899aabb, %rdi \n\t"
            "movq $0x5566778899aabbcc, %rsi \n\t"
            "movq $0x66778899aabbccdd, %rsp \n\t"
            "movq $0x778899aabbccddee, %rbp \n\t"
            "movq $0x8899aabbccddeeff, %r8  \n\t"
            "movq $0xffeeddccbbaa9988, %r9  \n\t"
            "movq $0xeeddccbbaa998877, %r10 \n\t"
            "movq $0xddccbbaa99887766, %r11 \n\t"
            "movq $0xccbbaa9988776655, %r12 \n\t"
            "movq $0xbbaa998877665544, %r13 \n\t"
            "movq $0xaa99887766554433, %r14 \n\t"
            "movq $0x9988776655443322, %r15 \n\t"
            );
    }
}

void *fun3(void* address){
    printf("address %#lx\n", address);
    printf("tid: %d\n",  gettid());
    char *p = mmap((void *)address, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (p == MAP_FAILED)
        handle_error("mmap");
    for (int i=0; i < MAP_SIZE; i++){
        p[i] = 0xff - (i%0x100);
    }

    while(1){
    __asm__("movq $0x33, %rax \n\t"
            "movq $0x1122334455667788, %rbx \n\t"
            "movq $0x2233445566778899, %rcx \n\t"
            "movq $0x33445566778899aa, %rdx \n\t"
            "movq $0x445566778899aabb, %rdi \n\t"
            "movq $0x5566778899aabbcc, %rsi \n\t"
            "movq $0x66778899aabbccdd, %rsp \n\t"
            "movq $0x778899aabbccddee, %rbp \n\t"
            "movq $0x8899aabbccddeeff, %r8  \n\t"
            "movq $0xffeeddccbbaa9988, %r9  \n\t"
            "movq $0xeeddccbbaa998877, %r10 \n\t"
            "movq $0xddccbbaa99887766, %r11 \n\t"
            "movq $0xccbbaa9988776655, %r12 \n\t"
            "movq $0xbbaa998877665544, %r13 \n\t"
            "movq $0xaa99887766554433, %r14 \n\t"
            "movq $0x9988776655443322, %r15 \n\t"
            );
    }
}


int main(void){
    pthread_t tid1, tid2, tid3;
    printf("Before Thread\n");
    pthread_create(&tid1, NULL, fun1, (void *)MAPPED_ADDRESS_1);
    pthread_create(&tid2, NULL, fun2, (void *)MAPPED_ADDRESS_2);
    pthread_create(&tid3, NULL, fun3, (void *)MAPPED_ADDRESS_3);
    printf("tid: %d\n",  gettid());
    printf("pid: %d\n",  getpid());
    pthread_join(tid1, NULL);
    printf("After Thread\n");
    exit(0);
}