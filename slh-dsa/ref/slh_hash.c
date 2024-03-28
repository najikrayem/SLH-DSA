#include "slh_hash.h"


#if CONF_SLH_SHAKE

#include "fips202.h"


#define shake_init_state                                            \
    char state[SHAKE256_STATE_LENGTH] = {0};                        \
    uint64_t *s = (uint64_t*)state;                                 \


#define shake_absorb(data, len)                                     \
    shake256_inc_absorb(s, (const char*)data, (size_t)len);         \


#define shake_sqeeze(out, len)                                      \
    shake256_inc_finalize(s);                                       \
    shake256_inc_squeeze((char*)out, (size_t)len, s);               \




void T_len(const char* pk_seed, const ADRS* adrs, const char* m, char* out){
    shake_init_state
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(adrs, sizeof(ADRS))
    shake_absorb(m, SLH_PARAM_len * SLH_PARAM_n)
    shake_sqeeze(out, SLH_PARAM_n)
}



void T_k(const char* pk_seed, const ADRS* adrs, const char* m, char* out){
    shake_init_state
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(adrs, sizeof(ADRS))
    shake_absorb(m, SLH_PARAM_k * SLH_PARAM_n)
    shake_sqeeze(out, SLH_PARAM_n)
}



void H(const char* pk_seed, const ADRS* adrs, const char* m, char* out){
    shake_init_state
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(adrs, sizeof(ADRS))
    shake_absorb(m, 2 * SLH_PARAM_n)
    shake_sqeeze(out, SLH_PARAM_n)
}


void H_split(const char* pk_seed, const ADRS* adrs, const char* m1, const char* m2, char* out){
    shake_init_state
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(adrs, sizeof(ADRS))
    shake_absorb(m1, SLH_PARAM_n)
    shake_absorb(m2, SLH_PARAM_n)
    shake_sqeeze(out, SLH_PARAM_n)
}



void H_msg(const char* randomizer, const char* pk_seed, const char* pk_root, const char* m, uint64_t mlen, char* out_hash){
    shake_init_state
    shake_absorb(randomizer, SLH_PARAM_n)
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(pk_root, PK_SEED_BYTES)
    shake_absorb(m, mlen)
    shake_sqeeze(out_hash, SLH_PARAM_m)
}



void PRF_msg(const char* sk_prf, const char* opt_rand, const char* m, uint64_t mlen, char* out_randomizer){
    shake_init_state
    shake_absorb(sk_prf, SK_PRF_BYTES)
    shake_absorb(opt_rand, SLH_PARAM_n)
    shake_absorb(m, mlen)
    shake_sqeeze(out_randomizer, SLH_PARAM_n)
}



void F(const char* pk_seed, const ADRS* adrs, const char* m, char* out){
    shake_init_state
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(adrs, sizeof(ADRS))
    shake_absorb(m, SLH_PARAM_n)
    shake_sqeeze(out, SLH_PARAM_n)
}



// void F_inplace(const char* pk_seed, const ADRS* adrs, char* m){
//     shake_init_state
//     shake_absorb(pk_seed, PK_SEED_BYTES)
//     shake_absorb(adrs, sizeof(ADRS))
//     shake_absorb(m, SLH_PARAM_n)
//     shake_sqeeze(m, SLH_PARAM_n)
// }



void PRF(const char* pk_seed, const char* sk_seed, const ADRS* adrs, char* out){
    shake_init_state
    shake_absorb(pk_seed, PK_SEED_BYTES)
    shake_absorb(adrs, sizeof(ADRS))
    shake_absorb(sk_seed, SK_SEED_BYTES)
    shake_sqeeze(out, SLH_PARAM_n)
}



#elif CONF_SLH_SHA3

// TODO

void H_msg(const char* randomizer, const char* pk_seed, const char* pk_root, const char* m, uint64_t mlen, char* out_hash){
    // Calculate the total length of input data
    size_t total_len = strlen(randomizer) + strlen(pk_seed) + strlen(pk_root) + mlen;

    // Concatenate all input data into a single buffer
    char* buffer = malloc(total_len);
    if (buffer == NULL) {
        return;
    }

    strcpy(buffer, randomizer);
    strcat(buffer, pk_seed);
    strcat(buffer, pk_root);
    strcat(buffer, m);

    // Calculate the SHA-256 hash of the input
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)buffer, total_len, hash);
    
    // Copy the hash to the output buffer
    memcpy(out_hash, hash, SHA256_DIGEST_LENGTH);

    free(buffer);
}

void PRF_msg(const char* sk_prf, const char* opt_rand, const char* m, uint64_t mlen, char* out_randomizer){
    const int n = SHA256_DIGEST_LENGTH;

    // Concatenate sk_prf, opt_rand, and m
    uint8_t input[n * 2 + mlen];
    memcpy(input, sk_prf, n);
    memcpy(input + n, opt_rand, n);
    memcpy(input + 2 * n, m, mlen);

    // Compute hash
    SHA256(input, sizeof(input), (unsigned char*)out_randomizer);
}
#endif