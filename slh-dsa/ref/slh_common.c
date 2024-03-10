#include "slh_common.h"
#include "slh_config.h"

void inline concat(char *fst, uint8_t fst_len, char *snd, uint8_t snd_len, char *out) {
    for (uint8_t i = 0; i < fst_len + snd_len; i++)
        if (i < fst_len)
            out[i] = fst[i];
        else
            out[i] = snd[i - fst_len];
}

// Ignore these for now, they are used for profiling. TODO NK.
void __cyg_profile_func_enter(void *this_fn, void *call_site) {}
void __cyg_profile_func_exit(void *this_fn, void *call_site) {}


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
