#include "slh_common.h"
#include "slh_config.h"
#include <stdint.h>

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
    // In case the byte string is too small return without doing any computation
    if (ceil(out_len * b / 8.0) > in_len) { 
        return;
    }

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
        out[i] = (char) fmodl(total >> bits, pow(2, b));
    }
}

// This function is inclomplete since many functions called by it are incomplete
void wots_PKFromSig(const char *sig, const char *m, const char *pk_seed, ADRS *adrs, char *pk_out) {
    uint64_t csum;
    char msg[SLH_PARAM_len1];
    char csum_bs[sizeof(uint64_t)];
    char csum_bw[SLH_PARAM_len2];
    char msg_csum[SLH_PARAM_len];
    char tmp[SLH_PARAM_len]; // remove as it should be included in adrs

    base_2b(m, SLH_PARAM_n, SLH_PARAM_lgw, SLH_PARAM_len1, msg);

    for (uint64_t i = 0; i < SLH_PARAM_len1; i++) {
        csum += (SLH_PARAM_w - 1) - msg[i];
    }

    csum = csum << ((8 - ((SLH_PARAM_len2 * SLH_PARAM_lgw) % 8)) % 8);
    toByte((char *) csum, csum_bs);
    base_2b(csum_bs, sizeof(uint64_t), SLH_PARAM_lgw, SLH_PARAM_len2, csum_bw);
    for (uint8_t i = 0; i < SLH_PARAM_len1; i++) {
        msg_csum[i] = msg[i];
    }
    for (uint8_t i = SLH_PARAM_len1; i < SLH_PARAM_len; i++) {
        msg_csum[i] = csum_bw[SLH_PARAM_len - i];
    }

    for (uint8_t i = 0; i < SLH_PARAM_len; i++) {
        //setChainAddress(NULL);ADRS setChainAddress function is not yet completed
        chain(&sig[i], msg[i], SLH_PARAM_w - 1 - msg[i], pk_seed, adrs, &tmp[i]);
    }
    ADRS wotspkADRS;
    setTypeAndClear(&wotspkADRS, WOTS_PK);
    setKeyPairAddress(&wotspkADRS, adrs->w1);
    // Set pk_out to result of t_l(pk_seed, wotspkADRS.tmp)
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

    for (uint8_t i = 0; i < SLH_PARAM_len; i++)
        sig_out[i] = sig[i];
    for (uint8_t i = SLH_PARAM_len; i < SLH_PARAM_len + SLH_PARAM_hprime; i++)
        sig_out[i] = auth[i - SLH_PARAM_len];
}
