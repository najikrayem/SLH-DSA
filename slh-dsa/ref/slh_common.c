#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>


#include "slh_common.h"
#include "slh_config.h"
#include "slh_hash.h"


void toInt(const char* x, uint8_t length, char* out){
    uint64_t total = 0;
    uint64_t i = 0;

    for (uint64_t i = 0; i < length; i++){
        total = 256 * total + x[i];
    }

    out = (char*) total;
}



void toByte(uint64_t x, char* out, uint8_t out_len){
    uint64_t total = x;

    for(uint64_t i = 0; i < strlen(out); i++){
        out[strlen(out) - 1 - i] = (char) (total % 256);
        total >>= 8;
    }
}



char* chain(const char* x, uint64_t i, uint64_t s, const char* pk_seed, ADRS* adrs, char* out){
    if ((i + s) >= SLH_PARAM_w) {
        return NULL;
    }
    
    memcpy(out, x, SLH_PARAM_n); 
    // MD REVISIT: probably better to use strncpy()? NK: dont use strcpy, it assumes null terminated strings. Use memcpy instead.   

    for (uint64_t j = i; j < i + s; j++) {
        setHashAddress(adrs, j);
        F_inplace(pk_seed, adrs, out);      //TODO NK
    }

    return out;    
}



void wots_PKgen(const char* sk_seed, const char* pk_seed, ADRS* adrs, char* pk_out){
    
    ADRS skADRS; // Copy address to create key generation key address
    memcpy(&skADRS, adrs, sizeof(ADRS));

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
    memcpy(&wotspkADRS, adrs, sizeof(ADRS));

    setTypeAndClear(&wotspkADRS, WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adrs));
    T_len(pk_seed, &wotspkADRS, tmp, pk_out); // Compress public key (TODO: Implement T_l)
}



char* xmss_node(const char* sk_seed, uint32_t i, uint32_t z, const char* pk_seed, ADRS* adrs, char* node){
    
    if(z > SLH_PARAM_hprime || i >= (1 << (SLH_PARAM_hprime - z))){
        return NULL;
    }

    if (z == 0){
        setTypeAndClear(adrs, WOTS_HASH);
        setKeyPairAddress(adrs, i);
        wots_PKgen(sk_seed, pk_seed, adrs, node);
    } else {
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

    // Buffer to hold the concatenation of an auth, a node, and another auth.
    // This is used to speed up the concatenation of the auths and the nodes
    // While computing the root form WOTS+ pk and auth.
    char auth_1_node_0_auth_2[3 * SLH_PARAM_n];
    char *auth_first = auth_1_node_0_auth_2;
    char *node_0 = auth_1_node_0_auth_2 + SLH_PARAM_n;
    char *auth_second = node_0;

    char tmp_node1[SLH_PARAM_n];

    wots_PKFromSig(sig, m, pk_seed, adrs, root_out);

    setTypeAndClear(adrs, TREE);
    setTreeIndex(adrs, idx);

    for(uint32_t k = 0; k < SLH_PARAM_hprime; k++){
        setTreeHeight(adrs, k+1);
        if(((idx >> k) & 1) == 0){
            setTreeIndex(adrs, getTreeIndex(adrs) >> 2);
            
            memcpy(auth_second, AUTH + (SLH_PARAM_h * k), SLH_PARAM_n);

            H(pk_seed, adrs, auth_second, tmp_node1); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
        } else{
            setTreeIndex(adrs, (getTreeIndex(adrs) - 1) >> 2);

            memcpy(auth_first, AUTH + (SLH_PARAM_h * k), SLH_PARAM_n);
            
            H(pk_seed, adrs, auth_first, tmp_node1); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
        }
        memcpy(node_0, tmp_node1, SLH_PARAM_n);
    }
    memcpy(root_out, node_0, SLH_PARAM_n);
}



void base_2b(const char *x, uint64_t in_len, uint8_t b, uint64_t out_len, char *out) {
    uint64_t in = 0;
    uint8_t bits = 0;
    uint64_t total = 0; // This will work for values of b specified in the standard

    for (uint64_t i = 0; i < out_len; i++) {
        while (bits < b) {
            total = (total << 8) + x[in];
            in++;
            bits += 8;
        }
        bits -= b;
        out[i] = (char) fmodl(total >> bits, (1 << b));
    }
}



void wots_PKFromSig(const char *sig, const char *m, const char *pk_seed, ADRS *adrs, char *pk_out) {
    uint64_t csum;
    char msg[SLH_PARAM_len1 + SLH_PARAM_len2];
    char csum_bs[CSUM_BYTES];
    char msg_csum[SLH_PARAM_len];
    char tmp[SLH_PARAM_len * SLH_PARAM_n];

    base_2b(m, SLH_PARAM_n, SLH_PARAM_lgw, SLH_PARAM_len1, msg);

    for (uint8_t i = 0; i < SLH_PARAM_len1; i++) {
        csum += (SLH_PARAM_w - 1) - msg[i];
    }

    csum = csum << ((8 - ((SLH_PARAM_len2 * SLH_PARAM_lgw) % 8)) % 8);
    toByte(csum, csum_bs, CSUM_BYTES);
    base_2b(csum_bs, CSUM_BYTES, SLH_PARAM_lgw, SLH_PARAM_len2, msg + SLH_PARAM_len1);

    for (uint32_t i = 0; i < SLH_PARAM_len; i++) {
        setChainAddress(adrs, i);
        chain((sig + i), msg[i], SLH_PARAM_w - 1 - msg[i], pk_seed, adrs, (tmp + (i * SLH_PARAM_n)));
    }
    ADRS wotspkADRS;
    memcpy(&wotspkADRS, adrs, sizeof(ADRS));
    setTypeAndClear(&wotspkADRS, WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adrs));
    T_len(pk_seed, &wotspkADRS, tmp, pk_out);
}



void fors_pkFromSig(const char *sig_fors, const char *md, const char *pk_seed, ADRS *adrs, char *pk_out) {
    
    const char *sk;
    
    char indices[SLH_PARAM_k];
    base_2b(md, SLH_SIGN_MD_LEN, SLH_PARAM_a, SLH_PARAM_k, indices);

    char node_0[SLH_PARAM_n];
    char node_1[SLH_PARAM_n];

    char auth_node_buffer[SLH_PARAM_n + FORS_AUTH_LEN];

    const char *auth;

    char root[SLH_PARAM_k * SLH_PARAM_n];
    for (uint8_t i = 0; i < SLH_PARAM_k; i++) {
        sk = getSK(sig_fors, i);
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, (i << SLH_PARAM_a) + indices[i]);
        F(pk_seed, adrs, sk, node_0);

        auth = getAUTH(sig_fors, i);
        for (uint8_t j = 0; j < SLH_PARAM_a; j++) {
            setTreeHeight(adrs, j+1);
            if (((indices[i] >> j) & 1) == 0) {
                // Even case
                setTreeIndex(adrs, (getTreeIndex(adrs) >> 2));
                
                memcpy(auth_node_buffer, node_0, SLH_PARAM_n);
                memcpy(auth_node_buffer + SLH_PARAM_n, auth + (j * SLH_PARAM_n), SLH_PARAM_n);

                H(pk_seed, adrs, auth_node_buffer, node_1);
            }
            else {
                // Odd case
                setTreeIndex(adrs, ((getTreeIndex(adrs) - 1) >> 1));

                memcpy(auth_node_buffer, auth + (j * SLH_PARAM_n), SLH_PARAM_n);
                memcpy(auth_node_buffer + SLH_PARAM_n, node_0, SLH_PARAM_n);

                H(pk_seed, adrs, auth_node_buffer, node_1);
            }
            memcpy(node_0, node_1, SLH_PARAM_n);
        }
        memcpy(root + (i * SLH_PARAM_n), node_0, SLH_PARAM_n);
    }

    ADRS forspkADRS;
    memcpy(&forspkADRS, adrs, sizeof(ADRS));

    setTypeAndClear(&forspkADRS, FORS_ROOTS);
    setKeyPairAddress(&forspkADRS, getKeyPairAddress(adrs));
    T_k(pk_seed, &forspkADRS, root, pk_out);
}

