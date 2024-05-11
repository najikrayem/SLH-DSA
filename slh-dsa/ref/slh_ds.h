#pragma once

#include <stdint.h>

#include "slh_config.h"

// PublicKey struct
typedef struct PublicKey{
    uint8_t seed[SLH_PARAM_n];
    uint8_t root[SLH_PARAM_n];
} PK;


// SecretKey struct
typedef struct SecretKey{
    uint8_t seed[SLH_PARAM_n];
    uint8_t prf [SLH_PARAM_n];
    PK pk;
} SK;


// Types of addresses
typedef enum {
    WOTS_HASH = 0,
    WOTS_PK,
    TREE,
    FORS_TREE,
    FORS_ROOTS,
    WOTS_PRF,
    FORS_PRF
} AddressType;


// Address struct
typedef struct Address{
    // All the following values must be encoded in big-endian format

    // Height of XMSS tree within hypertree. 0 ≤ layer < d
    uint8_t unused0[3];         //[0:3]
    uint8_t layer;              //[3]

    // Three words containing the position of an XMSS tree within a layer of
    // the hypertree. 0 ≤ address < 2^((d−1−layer)hprime). Since for any
    // configuration the value of address is less than 2^64, and big-endian
    // encoding is used, the address can be represented as a 64-bit integer,
    // while the third word is not used.
    uint32_t unused1;           //[4:8]
    uint64_t address;           //[8:16]
    
    // Address Type. Since we only have 7 types, we can split the word into
    // unused 3 bytes and 1 byte for the type to easily maintain the big-endian
    // encoding.
    uint8_t unused2[3];         //[16:19]
    uint8_t type;               //[19]

    // Three words. Interpretation depends on the type of address.
    uint32_t w1;                //[20:24]
    uint32_t w2;                //[24:28]
    uint32_t w3;                //[28:32]
} ADRS;
