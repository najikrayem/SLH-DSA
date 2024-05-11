
//#pragma once

#ifdef INSTRUMENTATION_ENABLED

#warning "Instrumentation enabled"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <execinfo.h>

#ifdef __QNX__
    #include <dlfcn.h>
    #include <sys/neutrino.h>
#else
    #include <dlfcn.h>
    #include <time.h>
    // TODO this only works to x86
    static __inline__ uint64_t ClockCycles(void)
        __attribute__((no_instrument_function));
    static __inline__ uint64_t ClockCycles(void) {
        unsigned int lo, hi;
        __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
        return ((uint64_t)hi << 32) | lo;
    }
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

    Dl_info func_info;
    dladdr(func, &func_info);

    if (func_info.dli_sname) {
        printf("FUNC: %s, \tCYCLES: %" PRIu64 "\n", func_info.dli_sname, tot_cycles);
    } else {
        printf("FUNC: %x, \tCYCLES: %" PRIu64 "\n", func, tot_cycles);
        // printf("FUNC: ");
        // print_function_name_from_address(caller);
        // printf(", \tCYCLES: %" PRIu64 "\n", tot_cycles);
    }

}

#endif
