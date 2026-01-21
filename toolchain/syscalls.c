#include "syscalls.h"
#include <sys/types.h>
#include <stdint.h>

hidden noplt void * __dl_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8  __asm__("r8")  = fd;
    register long r9  __asm__("r9")  = off;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(9), "D"(addr), "S"(len), "d"(prot), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );

    if (ret < 0) return (void*)-1;   
    return (void*)ret;
}


// SYS_munmap: 11
hidden noplt int __dl_munmap(void *addr, size_t len)
{
    long ret;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(11),       // SYS_munmap
          "D"(addr),     // rdi
          "S"(len)       // rsi
        : "rcx", "r11", "memory"
    );
    return (int)ret;
}

// SYS_mprotect: 10
hidden noplt int __dl_mprotect(void *addr, size_t len, int prot)
{
    long ret;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(10),       // SYS_mprotect
          "D"(addr),     // rdi
          "S"(len),      // rsi
          "d"(prot)      // rdx
        : "rcx", "r11", "memory"
    );

    return (int)ret;
}

hidden noplt int64_t __dl_read(uint32_t fd, char *buf, size_t count) {
    int64_t ret = 0;
    asm volatile (
        "movl %1, %%edi;"
        "movq %2, %%rsi;"
        "movq %3, %%rdx;"
        "movq $0, %%rax;" // SYS_read
        "syscall;"
        "movq %%rax, %0"
        : "=r" (ret)
        : "r" (fd), "r" (buf), "r" (count)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt uint64_t __dl_lseek(uint32_t fd, uint64_t offset, uint32_t origin) {
    uint64_t ret = 0;
    asm volatile (
        "movl %1, %%edi;"
        "movq %2, %%rsi;"
        "movl %3, %%edx;"
        "movq $0, %%rax;" // SYS_read
        "syscall;"
        "movq %%rax, %0"
        : "=r" (ret)
        : "r" (fd), "r" (offset), "r" (origin)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt int __dl_open(const char *pathname, int flags, int mode) {
    int ret = 0;
    asm volatile (
        "movq %1, %%rdi;"
        "movl %2, %%esi;"
        "movl %3, %%edx;"
        "movq $2, %%rax;" // SYS_open
        "syscall;"
        "movl %%eax, %0"
        : "=r" (ret)
        : "r" (pathname), "r" (flags), "r" (mode)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt int __dl_close(int fd) {
    int ret = 0;
    asm volatile (
        "movl %1, %%edi;"
        "movq $3, %%rax;" // SYS_close
        "syscall;"
        "movl %%eax, %0"
        : "=r" (ret)
        : "r" (fd)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt int __dl_stat(const char* path, struct stat* buf) {
    int ret = 0;
    asm volatile (
        "movq %1, %%rdi;"
        "movq %2, %%rsi;"
        "movq $4, %%rax;" // SYS_stat
        "syscall;"
        "movl %%eax, %0"
        : "=r" (ret)
        : "r" (path), "r" (buf)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt int __dl_fstat(int fd, struct stat* buf) {
    int ret = 0;
    asm volatile (
        "movl %1, %%edi;"
        "movq %2, %%rsi;"
        "movq $5, %%rax;" // SYS_fstat
        "syscall;"
        "movl %%eax, %0"
        : "=r" (ret)
        : "r" (fd), "r" (buf)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt int64_t __dl_readlink(const char *pathname, char *buf, size_t bufsize) {
    int64_t ret = 0;
    asm volatile (
        "movq %1, %%rdi;"
        "movq %2, %%rsi;"
        "movq %3, %%rdx;"
        "movq $89, %%rax;" // SYS_readlink
        "syscall;"
        "movq %%rax, %0"
        : "=r" (ret)
        : "r" (pathname), "r" (buf), "r" (bufsize)
        : "rcx", "r11", "rax"
    );
    return ret;
}

hidden noplt long __dl_get_tid_address(void)
{
    long ret;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(186)                 // SYS_gettid
        : "rcx", "r11", "memory"
    );

    // gettid normally never fails, but keep consistent error handling
    if (ret < 0) return -1;
    return ret;                   // returns TID
}

hidden noplt long __dl_set_tid_address(int *tidptr)
{
    long ret;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(218),                // SYS_set_tid_address
          "D"(tidptr)              // arg1 in rdi
        : "rcx", "r11", "memory"
    );

    // set_tid_address normally never fails, but keep consistent error handling
    if (ret < 0) return -1;
    return ret;                   // returns TID
}

#ifndef __NR_arch_prctl
#define __NR_arch_prctl 158
#endif

#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif
#ifndef ARCH_GET_FS
#define ARCH_GET_FS 0x1003
#endif

/* Set "thread pointer" (FS.base) to tp. Return 0 on success, -1 on error. */
hidden noplt long __dl_set_thread_area(void *tp)
{
    long ret;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(__NR_arch_prctl),
          "D"(ARCH_SET_FS),
          "S"((unsigned long)tp)
        : "rcx", "r11", "memory"
    );

    if (ret < 0) return -1;
    return 0;
}

/* Get current "thread pointer" (FS.base).
 * Return FS.base on success; (void*)-1 on error. */
hidden noplt void * __dl_get_thread_area(void)
{
    long ret;
    unsigned long base = 0;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(__NR_arch_prctl),
          "D"(ARCH_GET_FS),
          "S"(&base)
        : "rcx", "r11", "memory"
    );

    if (ret < 0) return (void *)-1;
    return (void *)base;
}
