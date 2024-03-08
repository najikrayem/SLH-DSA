#include "slh_common.h"
#include "slh_config.h"

void inline concat(char *fst, uint8_t fst_len, char *snd, uint8_t snd_len, char *out) {
    for (uint8_t i = 0; i < fst_len + snd_len; i++)
        if (i < fst_len)
            out[i] = fst[i];
        else
            out[i] = snd[i - fst_len];
}


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


void fors_sign(const char* md, const char* sk_seed, const char* pk_seed, const ADRS* adrs, char* sig_out){
    // TODO NK: this function is a big mess

    char* sig_tmp = sig_out;
    uint32_t s;
    uint64_t node_idx;

    char* indices[64];
    base_2b(md, SLH_SIGN_MD_LEN, SLH_PARAM_a, SLH_PARAM_k, indices);


    for (uint32_t i = 0; i < SLH_PARAM_k; i++) {
        fors_SKgen(sk_seed, pk_seed, adrs, (i << SLH_PARAM_a) + indices[i], sig_tmp);
        sig_tmp += SLH_PARAM_n;

        for (uint32_t j = 0; j < SLH_PARAM_a; j++) {

            s = (indices[i] >> j) ^ (uint32_t)1;
            node_idx = (i << (SLH_PARAM_a - j)) + s;

            fors_node(sk_seed, node_idx, j, pk_seed, adrs, sig_tmp);
            sig_tmp += SLH_PARAM_n;

        }
    }
}



void fors_SKgen(const char* sk_seed, const char* pk_seed, const ADRS* adrs, uint32_t idx, char* fors_sk){
    ADRS skADRS;
    memcpy(&skADRS, adrs, sizeof(ADRS));
    setTypeAndClear(&skADRS, FORS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(adrs));
    setTreeIndex(&skADRS, idx);
    PRF(pk_seed, sk_seed, &skADRS, fors_sk);
}


void toInt(const char* x, uint8_t length, char* out){
    uint64_t total = 0;
    uint64_t i = 0;

    for (uint64_t i = 0; i < length; i++){
        total = 256 * total + x[i];
    }

    out = (char*) total;
}

void toByte(uint64_t x, char* out){
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
    
    strcpy(out, x); 
    // MD REVISIT: probably better to use strncpy()?

    for (uint64_t j = i; j < i + s; j++) {
        setHashAddress(adrs, j);
        F_inplace(pk_seed, adrs, out);
    }

    return out;    
}

void wots_PKgen(const char* sk_seed, const char* pk_seed, ADRS* adrs, char* pk_out){
    
    ADRS skADRS = *adrs; // Copy address to create key generation key address
    setTypeAndClear(&skADRS, WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(skADRS));

    for (int i = 0; i <= SLH_PARAM_len - 1; ++i) {
        setChainAddress(&skADRS, i);
        char sk[SLH_PARAM_n];
        PRF(pk_seed, sk_seed, &skADRS, sk); // Compute secret value for chain i
        setChainAddress(&adrs, i);
        chain(sk, 0, SLH_PARAM_w - 1, pk_seed, adrs, &pk_out[i * SLH_PARAM_n]); // Compute public value for chain i
    }
    
    ADRS wotspkADRS = *adrs;
    setTypeAndClear(&wotspkADRS, WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(wotspkADRS));
    T_l(pk_seed, wotspkADRS, pk_out); // Compress public key (TODO: Implement T_l)
}

void wots_sign(const char* m, const char* sk_seed, const char* pk_seed, ADRS* adrs, char* sig_out){
    uint64_t csum = 0;

    // Message 'm' is converted into base 'w' representation and stored in 'msg'
    char msg[SLH_PARAM_len];
    base_2b(m, strlen(m), SLH_PARAM_w, SLH_PARAM_len1, msg);
    
    // Compute checksum by iterating over each character in 'msg'
    for (uint64_t i = 0; i <= SLH_PARAM_len1 - 1; ++i) {
        csum = csum + SLH_PARAM_w - 1 - msg[i];
    }
    
    csum = csum << ((8 - ((SLH_PARAM_len2 * SLH_PARAM_w) % 8)) % 8);  // Checksum is left-shifted to fit into bytes
    
    char csum_bytes[sizeof(csum)];
    toByte(csum, csum_bytes);  // Convert checksum into a byte array
    
    char csum_base_w[SLH_PARAM_len2];
    base_2b(csum_bytes, sizeof(csum), SLH_PARAM_w, SLH_PARAM_len2, csum_base_w);  // Convert csum to base 'w'
    memcpy(msg + SLH_PARAM_len1, csum_base_w, SLH_PARAM_len2);                    // csum in base 'w' is appended to the end of 'msg'
    
    ADRS skADRS = *adrs;
    setTypeAndClear(&skADRS, WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(adrs));    

    for (int i = 0; i <= SLH_PARAM_len - 1; ++i) {  // Loop generates signature for each segment of msg
        setChainAddress(&skADRS, i);                // Sets chain address in ADRS structure for each segment

        char sk[SLH_PARAM_n];
        PRF(pk_seed, sk_seed, &skADRS, sk);   // PRF is applied to the seed and ADFS structure to generate secret key value 'sk'
        
        setChainAddress(adrs, i);             // Set chain address for signature output

        chain(sk, 0, msg[i], pk_seed, adrs, &sig_out[i * SLH_PARAM_n]);   // Computes hash chain for the signature
    }
}

char* xmss_node(const char* sk_seed, uint32_t i, uint32_t z, const char* pk_seed, ADRS* adrs, char* node){
    
    if(z > SLH_PARAM_hprime || i >= pow(2, (SLH_PARAM_hprime - z))){
        return NULL;
    }

    if (z == 0){
        setTypeAndClear(&adrs, WOTS_HASH);
        setKeyPairAddress(&adrs, i);
        wots_PKgen(sk_seed, pk_seed, adrs, node);
    } else {
        char lnode[SLH_PARAM_n];
        char rnode[SLH_PARAM_n];
        
        if(!xmss_node(sk_seed, 2*i, z-1, pk_seed, adrs, lnode)){
            return NULL;
        }
        
        if(!xmss_node(sk_seed,(2*i) + 1, pk_seed, adrs, rnode)){
            return NULL;
        }
        
        // Prepare ADRS for the parent node computation
        setTypeAndClear(&adrs, TREE);
        setTreeHeight(adrs, z);
        setTreeIndex(adrs, i);
        
        char concatenated[2 * SLH_PARAM_n]; // Buffer to hold the concatenation of lnode and rnode
        memcpy(concatenated, lnode, SLH_PARAM_n);
        memcpy(concatenated + SLH_PARAM_n, rnode, SLH_PARAM_n);   

        // Hash the concatenated array and store the result in 'node'
        H(pk_seed, adrs, concatenated, node); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
    }

    return node;
}

void xmss_PKFromSig(uint32_t idx, const char* sig_xmss, const char* m, const char* pk_seed, ADRS* adrs, char* root_out){
    char* sig[len(sig_xmss)];
    char* AUTH[SLH_PARAM_n];

    setTypeAndClear(&adrs, WOTS_HASH);
    setKeyPairAddress(&adrs, idx);
    sig = getWOTSSig(&sig_xmss); // TODO: Revisit when getWOTSSIG is implemeted
    AUTH = getXMSSAUTH(&sig_xmss);
    wots_PKFromSig(sig, m, pk_seed, adrs, root_out[0]);

    setTypeAndClear(&adrs, TREE);
    setTreeIndex(&adrs, idk);

    for(uint64_t k = 0; k < SLH_PARAM_hprime; k++){
        setTreeHeight(adrs, k+1);
        if(idk/pow(2,k) % 2 == 0){
            setTreeIndex(adrs, getTreeIndex(adrs)/2);
            
            char concatenated[2 * SLH_PARAM_n]; // Buffer to hold the concatenation of root[0] and AUTH[k]
            memcpy(concatenated, root[0], SLH_PARAM_n);
            memcpy(concatenated + SLH_PARAM_n, AUTH[k], SLH_PARAM_n);
            
            H(pk_seed, adrs, concatenated, root_out); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
        } else{
            setTreeIndex(adrs, (getTreeIndex(adrs) - 1) /2);
            
            char concatenated[2 * SLH_PARAM_n]; // Buffer to hold the concatenation of AUTH[k] and root[0]
            memcpy(concatenated, AUTH[k], SLH_PARAM_n);
            memcpy(concatenated + SLH_PARAM_n, root[0], SLH_PARAM_n);
            
            H(pk_seed, adrs, concatenated, root_out); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
        }
        root_out[0] = root_out[1];
    }
}

char* fors_node(const char* sk_seed, uint64_t i, uint64_t z, const char* pk_seed, ADRS* adrs, char* node){
    if ((z >= SLH_PARAM_a) || (i >= SLH_PARAM_k * pow(2, (SLH_PARAM_a - z)))) {
        return NULL;
    }
    
    if (z == 0) {
        fors_SKgen(sk_seed, pk_seed, adrs, i, node);  // Generate the secret key part for the leaf node
        
        // Generate public key value from secret key (assuming F modifies node in-place)
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, i);
        F(pk_seed, adrs, node);

    } else {
        char lnode[SLH_PARAM_n];
        char rnode[SLH_PARAM_n];
        
        // Recursively compute the left child node
        if (!fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs, lnode)) {
            return NULL;
        }
        
        // Recursively compute the right child node
        if (!fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, rnode)) {
            return NULL;
        }

        // Prepare ADRS for the parent node computation
        setTreeHeight(adrs, z);
        setTreeIndex(adrs, i);

        // Concatenate lnode and rnode into a new buffer for H
        char concatenated[2 * SLH_PARAM_n]; // Buffer to hold the concatenation of lnode and rnode
        memcpy(concatenated, lnode, SLH_PARAM_n);
        memcpy(concatenated + SLH_PARAM_n, rnode, SLH_PARAM_n);

        // Hash the concatenated array and store the result in 'node'
        H(pk_seed, adrs, concatenated, node); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
    }
    
    return node;
}

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

void ht_sign(const char* m, const char* sk_seed, const char* pk_seed, uint64_t idx_tree, uint32_t idx_leaf, char* sig_out){

    // TODO
    // #if DATA_CHECKS_ENABLED
    //     if (m == NULL || sk_seed == NULL || pk_seed == NULL || sig_out == NULL){
    //         printf("ht_sign: NULL input\n");
    //         return;
    //     }
    // #endif

    ADRS adrs = {0};

    setTreeAddress(&adrs, idx_tree);

    char sig_ht [HT_SIG_LEN] = {0};
    char* sig_tmp = sig_ht;

    xmss_sign(m, sk_seed, idx_leaf, pk_seed, &adrs, sig_tmp);
    sig_tmp += XMSS_SIG_LEN;

    char root[SLH_PARAM_n] = {0};
    xmss_PKFromSig(idx_leaf, sig_tmp, m, pk_seed, &adrs, root);

    for(uint8_t j = 1; j < SLH_PARAM_d; j++){

        idx_leaf = ((uint32_t)idx_tree) && ((uint32_t)HPRIME_LSB_MASK);
        idx_tree >>= SLH_PARAM_hprime;

        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);

        xmss_sign(root, sk_seed, idx_leaf, pk_seed, &adrs, sig_tmp);

        if (j < SLH_PARAM_d - 1){
            xmss_PKFromSig(idx_leaf, sig_tmp, root, pk_seed, &adrs, root);
        }

        sig_tmp += XMSS_SIG_LEN;
        
    }
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

// This function is inclomplete since many functions called by it are incomplete
void wots_PKFromSig(const char *sig, const char *m, const char *pk_seed, ADRS *adrs, char *pk_out) {
    uint64_t csum;
    char msg[SLH_PARAM_len1];
    char csum_bs[sizeof(uint64_t)];
    char csum_bw[SLH_PARAM_len2];
    char msg_csum[SLH_PARAM_len];
    char tmp[SLH_PARAM_len];

    base_2b(m, SLH_PARAM_n, SLH_PARAM_lgw, SLH_PARAM_len1, msg);

    for (uint64_t i = 0; i < SLH_PARAM_len1; i++) {
        csum += (SLH_PARAM_w - 1) - msg[i];
    }

    csum = csum << ((8 - ((SLH_PARAM_len2 * SLH_PARAM_lgw) % 8)) % 8);
    toByte((char *) csum, csum_bs);
    base_2b(csum_bs, sizeof(uint64_t), SLH_PARAM_lgw, SLH_PARAM_len2, csum_bw);

    concat(msg, SLH_PARAM_len1, csum_bw, SLH_PARAM_len2, msg_csum);

    for (uint8_t i = 0; i < SLH_PARAM_len; i++) {
        //setChainAddress(adrs, i);
        chain(&sig[i], msg[i], SLH_PARAM_w - 1 - msg[i], pk_seed, adrs, &tmp[i]);
    }
    ADRS wotspkADRS = *adrs;
    setTypeAndClear(&wotspkADRS, WOTS_PK);
    //setKeyPairAddress(&wotspkADRS, getKeyPairAddress(adrs));
    //T_l(pk_seed, wotspkADRS, tmp, pk_out);
}

void xmss_sign(const char *m, const char *sk_seed, uint32_t idx, const char *pk_seed, ADRS *adrs, char *sig_out) {
    uint64_t k;
    char auth[SLH_PARAM_hprime];
    char sig[SLH_PARAM_len];
    
    for (uint64_t i = 0; i < SLH_PARAM_hprime; i++) {
        k = (idx / (1 << i)) ^ 1;
        xmss_node(sk_seed, k, i, pk_seed, adrs, &auth[i]);
    }

    setTypeAndClear(adrs, WOTS_HASH);
    setKeyPairAddress(adrs, idx);
    wots_sign(m, sk_seed, pk_seed, adrs, sig);

    concat(sig, SLH_PARAM_len, auth, SLH_PARAM_hprime, sig_out);
}

void fors_pkFromSig(const char *sig_fors, const char *md, const char *pk_seed, ADRS *adrs, char *pk_out) {
    char indices[SLH_PARAM_k];
    char node[2];
    char root[SLH_PARAM_k];
    char sk[SLH_PARAM_n];
    char auth[SLH_PARAM_n * SLH_PARAM_a];
    char concat_arr[2];

    ADRS forspkADRS;

    base_2b(md, SLH_PARAM_k * SLH_PARAM_a, SLH_PARAM_a, SLH_PARAM_k, indices);

    for (uint8_t i = 0; i < SLH_PARAM_k; i++) {
        getSK(sig_fors, i, sk);
        setTreeHeight(adrs, 0);
        setTreeIndex(i * (1 << SLH_PARAM_a) + indices[i])
        F(pk_seed, adrs, sk, &node[0])

        get_auth(sig_fors, i, auth);
        for (uint8_t j = 0; j < SLH_PARAM_a; j++) {
            setTreeHeight(adrs, j+1);
            if (indices[i] / (1 << j) & 1) {
                // Odd case
                setTreeIndex(adrs, (getTreeIndex(adrs) - 1) / 2);
                concat_arr[0] = auth[j];
                concat_arr[1] = node[0]
                H(pk_seed, adrs, concat_arr, &node[1]);
            }
            else {
                // Even case
                setTreeIndex(adrs, (getTreeIndex(adrs)) / 2);
                concat_arr[0] = node[0];
                concat_arr[1] = auth[j];
                H(pk_seed, adrs, concat_arr, &node[1]);
            }
            node[0] = node[1];
        }
        root[i] = node[0];
    }

    forspkADRS = *adrs;
    setTypeAndClear(&forspkADRS, FORS_ROOTS);
    setKeyPairAddress(&forspkADRS, getKeyPairAddress(adrs));
    T_k(pk_seed, forspkADRS, root, pk_out);
}



bool ht_verify(const char* m, const char* sig_ht, const char* pk_seed, uint64_t idx_tree, uint64_t idx_leaf, const char* pk_root){
    char* sig_tmp[HT_SIG_LEN] = {0};
    char* node[len(pk_root)] = {0};
    adrs = toByte(0, 32);

    setTreeAddress(&adrs, idx_tree);
    sig_tmp = getXMSSSignature(&sig_ht, 0);
    xmss_PKFromSig(idx_leaf, sig_tmp, m, pk_seed, &adrs, pk_root);

    for(uint64_t j = 0; j < SLH_PARAM_d; j++){
        idx_leaf = idx_tree % 2;
        idx_tree = idx_leaf >> SLH_PARAM_hprime;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);
        sig_tmp = getXMSSSignature(&sig_ht, j);
        xmss_PKFromSig(idx_leaf, sig_tmp, m, pk_seed, adrs, node);
    }

    if (node == pk_root){
        return true;
    }
    else{
        return false;
    }
}

