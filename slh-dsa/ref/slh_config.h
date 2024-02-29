#pragma once

/*
SLH-DSA parameter sets are defined as:
    - CONF_SLH_128s
    - CONF_SLH_128f
    - CONF_SLH_192s
    - CONF_SLH_192f
    - CONF_SLH_256s
    - CONF_SLH_256f


Equations for deriving some of the parameters:
    w           = 2 ^ lgw
    m           = ceil((h - hprime) / 8) + ceil(hprime / 8) + ceil((a * k) / 8)
    pk_bytes    = 2 * n
    sig_bytes   = n * (1 + k * (1 + a) + h + d * len)
    len1        = ceil((8 * n) / lgw)
    len2        = floor(log_2(len1 * (w - 1)) / lgw) + 1
    len         = len1 + len2


Some precomputions can be done to speed up the program:

    PRECOMP_01: Used in alg. 19 " slh_verify"
    PRECOMP_01  = ceil(a * k / 8) + ceil((h - (h/d))/8) + ceil(h/(8d))


*/


#define CONF_SLH_256f       // NK TODO  move this to CMakeLists.txt


#if     defined(CONF_SLH_128s)
    // TODO
#elif   defined(CONF_SLH_128f)
    // TODO
#elif   defined(CONF_SLH_192s)
    // TODO
#elif   defined(CONF_SLH_192f)
    // TODO
#elif   defined(CONF_SLH_256s)
    // TODO
#elif   defined(CONF_SLH_256f)

    #define SLH_PARAM_n             32
    #define SLH_PARAM_h             68
    #define SLH_PARAM_d             17
    #define SLH_PARAM_hprime        4
    #define SLH_PARAM_a             9
    #define SLH_PARAM_k             35
    #define SLH_PARAM_SEC_LVL       5
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             49
    #define SLH_PARAM_pk_bytes      64
    #define SLH_PARAM_sig_bytes     49856    
    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          64
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           67

    #define PRECOMP_01              49    

#endif


/*
TODO
SLH_DSA Hash Primitives can be defined as:
    - CONF_SLH_SHA2
    - CONF_SLH_SHAKE
*/





