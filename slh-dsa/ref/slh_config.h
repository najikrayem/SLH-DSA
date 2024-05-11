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
    d           = hypertree height
    w           = 2 ^ lgw
    m           = ceil((h - hprime) / 8) + ceil(hprime / 8) + ceil((a * k) / 8)
    pk_bytes    = 2 * n
    sig_bytes   = n * (1 + k * (1 + a) + h + d * len)
    len1        = ceil((8 * n) / lgw)
    len2        = floor(log_2(len1 * (w - 1)) / lgw) + 1
    len         = len1 + len2


Some precomputions can be done to speed up the program:

    FORS_SIG_LEN: Length of the FORS signature.
    FORS_SIG_LEN = k * (n * (a + 1))


    XMSS_SIG_LEN: Length of the XMSS signature.
    XMSS_SIG_LEN = n * (hprime + len)


    HPRIME_LSB_MASK: Mask of the hprime least significant bits.


    HT_SIG_LEN: Length of the HT signature.
    HT_SIG_LEN = d * XMSS_SIG_LEN


    SLH_SIGN_MD_LEN: Length of "md" in slh_sign.
    SLH_SIGN_MD_LEN = ceil((k * a) / 8)


    SLH_SIGN_TMPIDXTREE_LEN: Length of "tmp_idx_tree" in slh_sign.
    SLH_SIGN_TMPIDXTREE_LEN = ceil((h - (h / d)) / 8)


    SLH_SIGN_TMPIDXLEAF_LEN: Length of "tmp_idx_leaf" in slh_sign.
    SLH_SIGN_TMPIDXLEAF_LEN = ceil(h / (8 * d))


    SLH_SIGN_TREE_LSB_MASK: Mask of the least significant bits of the leaf
        index. Used in slh_sign to get rid of the modulo operation.
    SLH_SIGN_TREE_LSB_MASK = 2 ^ (h - (h / d)) - 1


    SLH_SIGN_LEAF_LSB_MASK: Mask of the least significant bits of the leaf
        index. Used in slh_sign to get rid of the modulo operation.
    SLH_SIGN_LEAF_LSB_MASK = 2 ^ (h / d) - 1


    CSUM_BYTES: Length of the checksum in bytes.
    CSUM_BYTES = ceil((len2 * lgw) / 8)


    FORS_AUTH_LEN: Length of each AUTH in FORS in bytes.
    FORS_AUTH_LEN = n * a
*/


#define CONF_SLH_256f       // NK TODO  move this to CMakeLists.txt

/*
TODO
SLH_DSA Hash Primitives can be defined as:
    - CONF_SLH_SHA2
    - CONF_SLH_SHAKE
*/

#define DATA_CHECKS_ENABLED 0       // NK TODO move this to CMakeLists.txt
#define DEBUG_ENABLED 0             // NK TODO move this to CMakeLists.txt
#define CONF_SLH_SHAKE 1            // NK TODO move this to CMakeLists.txt



#if     defined(CONF_SLH_128s)

    #define SLH_PARAM_n             16
    #define SLH_PARAM_h             63
    #define SLH_PARAM_d             7
    #define SLH_PARAM_hprime        9
    #define SLH_PARAM_a             12
    #define SLH_PARAM_k             14
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             30
    #define SLH_PARAM_sec_lvl       1
    #define SLH_PARAM_pk_bytes      32
    #define SLH_PARAM_sig_bytes     7856

    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          32
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           35

    #define XMSS_SIG_LEN            
    #define FORS_SIG_LEN            
    #define HT_SIG_LEN              
    #define HPRIME_LSB_MASK         
    #define SLH_SIGN_MD_LEN         
    #define SLH_SIGN_TMPIDXTREE_LEN 
    #define SLH_SIGN_TMPIDXLEAF_LEN 
    #define SLH_SIGN_TREE_LSB_MASK  
    #define SLH_SIGN_LEAF_LSB_MASK  
    #define CSUM_BYTES              1
    #define FORS_AUTH_LEN           192

#elif   defined(CONF_SLH_128f)

    #define SLH_PARAM_n             16
    #define SLH_PARAM_h             66
    #define SLH_PARAM_d             22
    #define SLH_PARAM_hprime        3
    #define SLH_PARAM_a             6
    #define SLH_PARAM_k             33
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             34
    #define SLH_PARAM_sec_lvl       1
    #define SLH_PARAM_pk_bytes      32
    #define SLH_PARAM_sig_bytes     17088

    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          32
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           35

    #define XMSS_SIG_LEN            
    #define FORS_SIG_LEN            
    #define HT_SIG_LEN              
    #define HPRIME_LSB_MASK         
    #define SLH_SIGN_MD_LEN         
    #define SLH_SIGN_TMPIDXTREE_LEN 
    #define SLH_SIGN_TMPIDXLEAF_LEN 
    #define SLH_SIGN_TREE_LSB_MASK  
    #define SLH_SIGN_LEAF_LSB_MASK  
    #define CSUM_BYTES              1
    #define FORS_AUTH_LEN           96

#elif   defined(CONF_SLH_192s)

    #define SLH_PARAM_n             24
    #define SLH_PARAM_h             63
    #define SLH_PARAM_d             7
    #define SLH_PARAM_hprime        9
    #define SLH_PARAM_a             14
    #define SLH_PARAM_k             17
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             39
    #define SLH_PARAM_sec_lvl       3
    #define SLH_PARAM_pk_bytes      48
    #define SLH_PARAM_sig_bytes     16224

    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          48
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           51

    #define XMSS_SIG_LEN            
    #define FORS_SIG_LEN            
    #define HT_SIG_LEN              
    #define HPRIME_LSB_MASK         
    #define SLH_SIGN_MD_LEN         
    #define SLH_SIGN_TMPIDXTREE_LEN 
    #define SLH_SIGN_TMPIDXLEAF_LEN 
    #define SLH_SIGN_TREE_LSB_MASK  
    #define SLH_SIGN_LEAF_LSB_MASK  
    #define CSUM_BYTES              1
    #define FORS_AUTH_LEN           336

#elif   defined(CONF_SLH_192f)

    #define SLH_PARAM_n             24
    #define SLH_PARAM_h             66
    #define SLH_PARAM_d             22
    #define SLH_PARAM_hprime        3
    #define SLH_PARAM_a             8
    #define SLH_PARAM_k             33
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             42
    #define SLH_PARAM_sec_lvl       3
    #define SLH_PARAM_pk_bytes      48
    #define SLH_PARAM_sig_bytes     35664

    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          48
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           51

    #define XMSS_SIG_LEN            
    #define FORS_SIG_LEN            
    #define HT_SIG_LEN              
    #define HPRIME_LSB_MASK         
    #define SLH_SIGN_MD_LEN         
    #define SLH_SIGN_TMPIDXTREE_LEN 
    #define SLH_SIGN_TMPIDXLEAF_LEN 
    #define SLH_SIGN_TREE_LSB_MASK  
    #define SLH_SIGN_LEAF_LSB_MASK  
    #define CSUM_BYTES              1
    #define FORS_AUTH_LEN           192

#elif   defined(CONF_SLH_256s)
    
    #define SLH_PARAM_n             32
    #define SLH_PARAM_h             64
    #define SLH_PARAM_d             8
    #define SLH_PARAM_hprime        8
    #define SLH_PARAM_a             14
    #define SLH_PARAM_k             22
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             47
    #define SLH_PARAM_sec_lvl       5
    #define SLH_PARAM_pk_bytes      64
    #define SLH_PARAM_sig_bytes     29792

    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          64
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           67

    #define XMSS_SIG_LEN            
    #define FORS_SIG_LEN            
    #define HT_SIG_LEN              
    #define HPRIME_LSB_MASK         
    #define SLH_SIGN_MD_LEN         
    #define SLH_SIGN_TMPIDXTREE_LEN 
    #define SLH_SIGN_TMPIDXLEAF_LEN 
    #define SLH_SIGN_TREE_LSB_MASK  
    #define SLH_SIGN_LEAF_LSB_MASK  
    #define CSUM_BYTES              1
    #define FORS_AUTH_LEN           448

#elif   defined(CONF_SLH_256f)

    #define SLH_PARAM_n             32
    #define SLH_PARAM_h             68
    #define SLH_PARAM_d             17
    #define SLH_PARAM_hprime        4
    #define SLH_PARAM_a             9
    #define SLH_PARAM_k             35
    #define SLH_PARAM_lgw           4
    #define SLH_PARAM_m             49
    #define SLH_PARAM_sec_lvl       5
    #define SLH_PARAM_pk_bytes      64
    #define SLH_PARAM_sig_bytes     49856

    #define SLH_PARAM_w             16
    #define SLH_PARAM_len1          64
    #define SLH_PARAM_len2          3
    #define SLH_PARAM_len           67

    #define XMSS_SIG_LEN            2272
    #define FORS_SIG_LEN            11200
    #define HT_SIG_LEN              38624
    #define HPRIME_LSB_MASK         0b1111
    #define SLH_SIGN_MD_LEN         40
    #define SLH_SIGN_TMPIDXTREE_LEN 8
    #define SLH_SIGN_TMPIDXLEAF_LEN 1
    #define SLH_SIGN_TREE_LSB_MASK  (~((uint64_t)0))
    #define SLH_SIGN_LEAF_LSB_MASK  0xF
    #define CSUM_BYTES              2
    #define FORS_AUTH_LEN           288

#endif


#define PK_SEED_BYTES               SLH_PARAM_n
#define PK_ROOT_BYTES               SLH_PARAM_n
#define SK_SEED_BYTES               SLH_PARAM_n
#define SK_PRF_BYTES                SLH_PARAM_n


#if CONF_SLH_SHAKE

    #define SHAKE256_STATE_LENGTH   208         //in bytes = 26*8 = 208

#endif


