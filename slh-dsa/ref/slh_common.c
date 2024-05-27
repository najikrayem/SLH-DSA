#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <math.h>


#include "slh_common.h"
#include "slh_config.h"
#include "slh_hash.h"

// #if INSTRUMENTATION_ENABLED
//     #include "cyg_instrumentation.h"
// #endif


uint64_t toInt(const uint8_t *X, uint8_t n) {
    if (n == 8)
        return BE64(*(const uint64_t *)X);

    if (n == 4)
        return BE32(*(const uint32_t *)X);

    uint64_t total = 0;
    for(uint8_t i = 0; i < n; i++) {
        total = (total << 8) + X[i];
    }
    return total;
}



void toByte(uint64_t x, char* out, uint8_t out_len){
    uint64_t total = x;

    for(uint64_t i = 0; i < out_len; i++){
        out[out_len - 1 - i] = (uint8_t) total;
        total >>= 8;
    }
}



char* chain(const char* x, uint32_t i, uint32_t s, const char* pk_seed, ADRS* adrs, char* out){
    if ((i + s) >= SLH_PARAM_w) {
        #if DEBUG_ENABLED
            printf("Invalid input for chain, returning NULL\n");
        #endif
        return NULL;
    }

    char tmp[SLH_PARAM_n];
    memcpy(tmp, x, SLH_PARAM_n);        //TODO NK

    for (uint32_t j = i; j < (i + s); j++) {
        setHashAddress(adrs, j);
        F(pk_seed, adrs, tmp, tmp);
    }

    memcpy(out, tmp, SLH_PARAM_n); //TODO NK

    return out;    
}



void wots_PKgen(const char* sk_seed, const char* pk_seed, ADRS* adrs, char* pk_out){
    
    ADRS skADRS; // Copy address to create key generation key address
    memcpy(&skADRS, adrs, sizeof(ADRS));        //TODO NK

    setTypeAndClear(&skADRS, WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(adrs));

    char sk[SLH_PARAM_n];
    char tmp[SLH_PARAM_len * SLH_PARAM_n];
    char *tmp_tmp = tmp;

    for (uint32_t i = 0; i < SLH_PARAM_len; i++) {
        setChainAddress(&skADRS, i);
        PRF(pk_seed, sk_seed, &skADRS, sk); // Compute secret value for chain i
        setChainAddress(adrs, i);
        chain(sk, 0, SLH_PARAM_w - 1, pk_seed, adrs, tmp_tmp); // Compute public value for chain i
        tmp_tmp += SLH_PARAM_n;
    }
    
    ADRS wotspkADRS;
    memcpy(&wotspkADRS, adrs, sizeof(ADRS));    //TODO NK

    setTypeAndClear(&wotspkADRS, WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adrs));
    T_len(pk_seed, &wotspkADRS, tmp, pk_out); // Compress public key (TODO: Implement T_l)
}



char* xmss_node(const char* sk_seed, uint32_t i, uint32_t z, const char* pk_seed, ADRS* adrs, char* node){
    
    if((z > SLH_PARAM_hprime) || (i >= (1 << (SLH_PARAM_hprime - z)))){
        #if DEBUG_ENABLED
            printf("Invalid input for xmss_node, returning NULL\n");
        #endif
        return NULL;
    }

    if (z != 0){
        
        char lrnode[SLH_PARAM_n + SLH_PARAM_n]; // Buffer to hold the concatenation of lnode and rnode
        char *lnode = lrnode;
        char *rnode = lrnode + SLH_PARAM_n;
        
        xmss_node(sk_seed, 2*i, z-1, pk_seed, adrs, lnode);
        
        xmss_node(sk_seed,(2*i) + 1, z-1, pk_seed, adrs, rnode);
        
        // Prepare ADRS for the parent node computation
        setTypeAndClear(adrs, TREE);
        setTreeHeight(adrs, z);
        setTreeIndex(adrs, i);

        // Hash the concatenated array and store the result in 'node'
        H(pk_seed, adrs, lrnode, node); // MD REVISIT: this might need to change based on how H is implemented/it's parameters

    } else {

        setTypeAndClear(adrs, WOTS_HASH);
        setKeyPairAddress(adrs, i);
        wots_PKgen(sk_seed, pk_seed, adrs, node);

    }

    return node;
}



void xmss_PKFromSig(uint32_t idx, const char* sig_xmss, const char* m, const char* pk_seed, ADRS* adrs, char* root_out){

    setTypeAndClear(adrs, WOTS_HASH);
    setKeyPairAddress(adrs, idx);
    
    // len * n bytes
    const char* sig = getWOTSSig(sig_xmss); // TODO: Revisit when getWOTSSIG is implemeted
    // each auth is n bytes long and there are hprime of them for a total of hprime * n bytes
    const char* AUTH = getXMSSAUTH(sig_xmss);

    wots_PKFromSig(sig, m, pk_seed, adrs, root_out);

    setTypeAndClear(adrs, TREE);
    setTreeIndex(adrs, idx);

    for(uint32_t k = 0; k < SLH_PARAM_hprime; k++){
        setTreeHeight(adrs, k+1);

        if(((idx >> k) & 1) == 0){
            // Even case
            setTreeIndex(adrs, getTreeIndex(adrs) >> 1);
            H_split(pk_seed, adrs, root_out, AUTH + (SLH_PARAM_n * k), root_out); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
        
        } else{
            // Odd case
            setTreeIndex(adrs, (getTreeIndex(adrs) - 1) >> 1);    
            H_split(pk_seed, adrs, AUTH + (SLH_PARAM_n * k), root_out, root_out); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
        
        }
    }
}


//TODO Nk: b is 9 max, so we can use uint8_t for b, and uint16_t for each out element.
// outlen is 64 max, so we can use uint8_t for out_len
void base_2b(const char *x, uint64_t in_len, uint8_t b, uint8_t out_len, uint16_t *out) {
    uint64_t in = 0;
    uint64_t bits = 0;

    uint16_t mask = (1 << b) - 1;

    uint64_t total = 0; // This will work for values of b specified in the standard
    for (uint8_t i = 0; i < out_len; i++) {
        while (bits < b) {
            total = (total << 8) + (uint8_t)(x[in]);
            in++;
            bits += 8;
        }
        bits -= b;
        out[i] = ((total >> bits) & mask);
    }
}



void wots_PKFromSig(const char *sig, const char *m, const char *pk_seed, ADRS *adrs, char *pk_out) {
    uint64_t csum = 0;
    
    //char msg_csum[SLH_PARAM_len];

    uint16_t msg[SLH_PARAM_len1 + SLH_PARAM_len2];
    base_2b(m, SLH_PARAM_n, SLH_PARAM_lgw, SLH_PARAM_len1, msg);

    // calculate checksum
    for (uint8_t i = 0; i < SLH_PARAM_len1; i++) {
        csum += (SLH_PARAM_w - 1) - msg[i];
    }

    csum = csum << ((8 - ((SLH_PARAM_len2 * SLH_PARAM_lgw) & 0b111)) & 0b111);

    char csum_bs[CSUM_BYTES];
    toByte(csum, csum_bs, CSUM_BYTES);
    base_2b(csum_bs, CSUM_BYTES, SLH_PARAM_lgw, SLH_PARAM_len2, msg + SLH_PARAM_len1);

    char tmp[SLH_PARAM_len * SLH_PARAM_n];
    for (uint32_t i = 0; i < SLH_PARAM_len; i++) {
        setChainAddress(adrs, i);
        chain(( sig + (i * SLH_PARAM_n)),
                msg[i],
                (SLH_PARAM_w - 1) - msg[i],
                pk_seed,
                adrs,
                (tmp + (i * SLH_PARAM_n)));
    }

    ADRS wotspkADRS;
    memcpy(&wotspkADRS, adrs, sizeof(ADRS));
    setTypeAndClear(&wotspkADRS, WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adrs));
    T_len(pk_seed, &wotspkADRS, tmp, pk_out);
}



void fors_pkFromSig(const char *sig_fors, const char *md, const char *pk_seed, ADRS *adrs, char *pk_out) {
    
    uint16_t indices[SLH_PARAM_k];
    base_2b(md, SLH_SIGN_MD_LEN, SLH_PARAM_a, SLH_PARAM_k, indices);

    const char *sk;

    char node_0[SLH_PARAM_n];
    char node_1[SLH_PARAM_n];

    char auth_node_buffer[SLH_PARAM_n + FORS_AUTH_LEN];

    const char *auth;

    char root[SLH_PARAM_k * SLH_PARAM_n];
    char *root_tmp = root;

    for (uint8_t i = 0; i < SLH_PARAM_k; i++) {
        sk = getSK(sig_fors, i);
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, (i << SLH_PARAM_a) + (uint32_t)(indices[i]));        //TODO NK are we reading indices[i] correctly?
        F(pk_seed, adrs, sk, node_0);

        auth = getAUTH(sig_fors, i);

        // #if DEBUG_ENABLED
        //     printf("Node 0, i = %u: ", i);
        //     for (uint8_t j = 0; j < SLH_PARAM_n; j++) {
        //         printf("%u ", (uint8_t)node_0[j]);
        //     }
        //     printf("\n");
        //     printf("Auth = ");
        //     for (uint8_t j = 0; j < SLH_PARAM_n; j++) {
        //         printf("%u ", (uint8_t)auth[j]);
        //     }
        //     printf("\n");
        // #endif


        for (uint8_t j = 0; j < SLH_PARAM_a; j++) {
            setTreeHeight(adrs, j+1);

            if (((indices[i] >> j) & 1) == 0) {
                // Even case
                setTreeIndex(adrs, (getTreeIndex(adrs) >> 1));
                H_split(pk_seed, adrs, node_0, auth, node_0);
            }
            else {
                // Odd case
                setTreeIndex(adrs, ((getTreeIndex(adrs) - 1) >> 1));
                H_split(pk_seed, adrs, auth, node_0, node_0);
            }

            // #if DEBUG_ENABLED
            //     printf("Node 0, j = %u, case = %u, treeidx = %u: ", j, ((indices[i] >> j) & 1), getTreeIndex(adrs));
            //     for (uint8_t k = 0; k < SLH_PARAM_n; k++) {
            //         printf("%u ", (uint8_t)node_0[k]);
            //     }
            //     printf("\n");
            //     printf("Auth = ");
            //     for (uint8_t k = 0; k < SLH_PARAM_n; k++) {
            //         printf("%u ", (uint8_t)auth[k]);
            //     }
            //     printf("\n");
            // #endif


            auth += SLH_PARAM_n;
        }
        memcpy(root_tmp, node_0, SLH_PARAM_n);      //TODO NK
        root_tmp += SLH_PARAM_n;
    }

    ADRS forspkADRS;
    memcpy(&forspkADRS, adrs, sizeof(ADRS));

    setTypeAndClear(&forspkADRS, FORS_ROOTS);
    setKeyPairAddress(&forspkADRS, getKeyPairAddress(adrs));
    T_k(pk_seed, &forspkADRS, root, pk_out);
}

