#include <string.h>

#include "slh_verify.h"
#include "slh_hash.h"

/**
 * @brief Get a pointer to the randomizer in the signature [0:n]
*/
static inline const char* getR(const char* sig){
    return sig;}

/**
 * @brief Get a pointer to the FORS signature in the signature
 * [n:n + FORS_SIG_LEN]
*/
static inline const char* getSIG_FORS(const char* sig){
    return sig + SLH_PARAM_n;}

/**
 * @brief Get a pointer to the Hypertree signature in the signature
 * [n + FORS_SIG_LEN:n + FORS_SIG_LEN + HT_SIG_LEN]
*/
static inline const char* getSIG_HT(const char* sig){
    return sig + SLH_PARAM_n + FORS_SIG_LEN;}


/**
 * @brief Get a pointer to the XMSS signature at a given layer within the
 * hypertree signature. Each XMSS signature is of length n * (hprime + len), and
 * there are d of them in the hypertree signature. 
*/
static inline const char* getXMSSSignature (const char* sig_ht, uint8_t layer){
    return sig_ht + (layer * (SLH_PARAM_n * (SLH_PARAM_hprime + SLH_PARAM_len)));}



// Algorithm 12
/**
 * @brief Verify a hypertree signature
 * 
 * @param m Pointer to the message. Must be n bytes long.
 * @param sig_ht Pointer to the hypertree signature. Must be n*(h + d * len) bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param idx_tree Index of the XMSS tree at the lowest hypertree level. Must be less 2^(h - hprime).
 * @param idx_leaf Index of the WOTS+ key within the XMSS tree. TODO
 * @param pk_root Pointer to the root of the XMSS tree. Must be n bytes long.
 * 
 * @return bool true if the signature is valid, false otherwise.
 * 
*/
bool ht_verify(const char* m, const char* sig_ht, const char* pk_seed, uint64_t idx_tree, uint64_t idx_leaf, const char* pk_root){

    ADRS adrs = {0};
    setTreeAddress(&adrs, idx_tree);

    const char* sig_tmp = getXMSSSignature(sig_ht, 0);

    char tmp_node_1[SLH_PARAM_n];
    char tmp_node_2[SLH_PARAM_n];

    xmss_PKFromSig(idx_leaf, sig_tmp, m, pk_seed, &adrs, tmp_node_1);

    for(uint8_t j = 0; j < SLH_PARAM_d; j++){
        idx_leaf = idx_tree & HPRIME_LSB_MASK;
        idx_tree >>= SLH_PARAM_hprime;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);
        sig_tmp = getXMSSSignature(sig_ht, j);

        // If j is even
        if ((j & 1) == 0){
            // Check if xmss_PKFromSig can be done in place
            xmss_PKFromSig(idx_leaf, sig_tmp, tmp_node_1, pk_seed, &adrs, tmp_node_2);
        } else {
            xmss_PKFromSig(idx_leaf, sig_tmp, tmp_node_2, pk_seed, &adrs, tmp_node_1);
        }
    }

    // if d-1 is even 
    if (((SLH_PARAM_d - 1) & 1) == 0){
        return (memcmp(tmp_node_2, pk_root, SLH_PARAM_n) == 0);
    } else {
        return (memcmp(tmp_node_1, pk_root, SLH_PARAM_n) == 0);
    }
}



bool slh_verify(const char *msg, uint64_t msg_len, const char *sig, const PK *pk){
    // TODO NK: checking signature length might be a security requirement
    // TODO NK: verify and sign share a lot of code, maybe refactor

    ADRS adrs = {0};

    const char* R = getR(sig);                    // Pointer to randomizer
    const char* sig_fors = getSIG_FORS(sig);      // Pointer to FORS signature
    const char* sig_ht = getSIG_HT(sig);          // Pointer to HT signature

    // Compute message digest
    char digest[SLH_PARAM_m];
    H_msg(R, pk->seed, pk->root, msg, msg_len, digest);

    // [ 0 : SLH_SIGN_MD_LEN ]
    char* md = digest;

    // [ SLH_SIGN_MD_LEN : SLH_SIGN_MD_LEN + SLH_SIGN_TMPIDXTREE_LEN]
    char* tmp_idx_tree = digest + SLH_SIGN_MD_LEN;

    // [ SLH_SIGN_MD_LEN + SLH_SIGN_TMPIDXTREE_LEN : SLH_SIGN_MD_LEN + SLH_SIGN_TMPIDXTREE_LEN + SLH_SIGN_TMPIDXLEAF_LEN]
    char* tmp_idx_leaf = tmp_idx_tree + SLH_SIGN_TMPIDXTREE_LEN;

    // Interpret it as a big-endian integer, and take the modulo.
    uint64_t idx_tree = toInt(tmp_idx_tree, SLH_SIGN_TMPIDXTREE_LEN);
    idx_tree = idx_tree & SLH_SIGN_TREE_LSB_MASK;

    // Interpret it as a big-endian integer, and take the modulo.
    uint16_t idx_leaf = toInt(tmp_idx_leaf, SLH_SIGN_TMPIDXLEAF_LEN);
    idx_leaf = idx_leaf & SLH_SIGN_LEAF_LSB_MASK;

    setTreeAddress(&adrs, idx_tree);
    setTypeAndClear(&adrs, FORS_TREE);
    setKeyPairAddress(&adrs, idx_leaf);


    char PK_fors[SLH_PARAM_n];
    fors_pkFromSig(sig_fors, md, pk->seed, &adrs, PK_fors);

    // Verify hypertree
    return ht_verify(PK_fors, sig_ht, pk->seed, idx_tree, idx_leaf, pk->root);

}