#include "slh_verify.h"

/**
 * @brief Get a pointer to the randomizer in the signature [0:n]
*/
inline char* getR(char* sig){
    return sig;}

/**
 * @brief Get a pointer to the FORS signature in the signature
 * [n:n + FORS_SIG_LEN]
*/
inline char* getSIG_FORS(char* sig){
    return sig + SLH_PARAM_n;}

/**
 * @brief Get a pointer to the Hypertree signature in the signature
 * [n + FORS_SIG_LEN:n + FORS_SIG_LEN + HT_SIG_LEN]
*/
inline char* getSIG_HT(char* sig){
    return sig + SLH_PARAM_n + FORS_SIG_LEN;}


bool slh_verify(const char *msg, uint64_t msg_len, const char *sig, const PK *pk){
    // TODO NK: checking signature length might be a security requirement
    // TODO NK: verify and sign share a lot of code, maybe refactor

    ADRS adrs = {0};

    char* R = getR(sig);                    // Pointer to randomizer
    char* sig_fors = getSIG_FORS(sig);      // Pointer to FORS signature
    char* sig_ht = getSIG_HT(sig);          // Pointer to HT signature

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
    uint64_t idx_tree;
    toInt(tmp_idx_tree, SLH_SIGN_TMPIDXTREE_LEN, *(char*)idx_tree);
    idx_tree = idx_tree & SLH_SIGN_TREE_LSB_MASK;

    // Interpret it as a big-endian integer, and take the modulo.
    uint16_t idx_leaf;
    toInt(tmp_idx_leaf, SLH_SIGN_TMPIDXLEAF_LEN, *(char*)idx_leaf);
    idx_leaf = idx_leaf & SLH_SIGN_LEAF_LSB_MASK;

    setTreeAddress(&adrs, idx_tree);
    setTypeAndClear(&adrs, FORS_TREE);
    setKeyPairAddress(&adrs, idx_leaf);


    char* PK_fors[SLH_PARAM_n];
    fors_pkFromSig(sig_fors, md, pk->seed, &adrs, PK_fors);

    // Verify hypertree
    return ht_verify(PK_fors, sig_ht, pk->seed, idx_tree, idx_leaf, pk->root);

}