
//#pragma once

#ifdef INSTRUMENTATION_ENABLED

#warning "Instrumentation enabled"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <execinfo.h>
#include <dlfcn.h>

#ifdef __QNX__
    #include <sys/neutrino.h>
#else

    #include <time.h>

    // check if arm or x86
    #if defined(__arm__) || defined(__aarch64__)
    
        static __inline__ uint64_t ClockCycles(void)
            __attribute__((no_instrument_function));
        static __inline__ uint64_t ClockCycles(void) {
            unsigned int value;
            __asm__ __volatile__ ("mrs %0, PMCCNTR_EL0" : "=r" (value));
            return value;
        }
    
    #elif defined(__x86_64__) || defined(__i386__)
        
        static __inline__ uint64_t ClockCycles(void)
            __attribute__((no_instrument_function));
        static __inline__ uint64_t ClockCycles(void) {
            unsigned int lo, hi;
            __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
            return ((uint64_t)hi << 32) | lo;
        }

    #endif
#endif



void __cyg_profile_func_enter(void *func, void *caller)
    __attribute__((no_instrument_function));

void __cyg_profile_func_exit(void *func, void *caller)
    __attribute__((no_instrument_function));

uint64_t start_cycles[64];
uint8_t current_depth = 0;

void __cyg_profile_func_enter(void *func, void *caller){
    start_cycles[current_depth] = ClockCycles();
    current_depth++;
}

void __cyg_profile_func_exit(void *func, void *caller) {
    uint64_t end_cycles = ClockCycles();

    current_depth--;
    uint64_t tot_cycles = end_cycles - start_cycles[current_depth];

    printf("FUNC: %p", func);
    printf(", \tCYCLES: %" PRIu64 "\n", tot_cycles);


    // Dl_info func_info;
    // dladdr(func, &func_info);

    // if (func_info.dli_sname) {
    //     printf("FUNC: %s, \tCYCLES: %" PRIu64 "\n", func_info.dli_sname, tot_cycles);
    // } else {
    //     printf("FUNC: %x, \tCYCLES: %" PRIu64 "\n", func, tot_cycles);
    // }

}

#endif
