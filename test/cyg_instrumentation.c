#if INSTRUMENTATION_ENABLED

    #include <dlfcn.h>
    #include <stdio.h>
    #include <sys/neutrino.h>
    #include <inttypes.h>

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
            printf("FUNC: %p, \tCYCLES: %" PRIu64 "\n", func, tot_cycles);
        }

    }

#endif // INSTRUMENTATION_ENABLED