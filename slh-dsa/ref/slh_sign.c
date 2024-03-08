#include "slh_sign.h"

void slh_sign(const char* msg, uint64_t msg_len, const SK* sk, char* sig){
    ADRS adrs = {0};

    char randByte;
    randBytes(&randByte, 1);

    char *opt_rand;
    char new_rand[SLH_PARAM_n];

    if (randByte > 127){
        randBytes(new_rand, SLH_PARAM_n);
        opt_rand = new_rand;
    } else {
        opt_rand = sk->pk.seed;
    }

    char* sig_tmp = sig;

    // Store randomizer at the beginning of the signature
    PRF_msg(sk->prf, opt_rand, msg, msg_len, sig_tmp);
    sig_tmp += SLH_PARAM_n;


    // Compute message digest
    char digest[SLH_PARAM_m];
    H_msg(sig, sk->pk.seed, sk->pk.root, msg, msg_len, digest);

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

    char* sig_fors = sig_tmp;
    fors_sign(md, sk->seed, sk->pk.seed, &adrs, sig_fors);
    sig_tmp += FORS_SIG_LEN;

    // Get FORS Key
    char* PK_fors[SLH_PARAM_n];
    fors_pkFromSig(sig_fors, md, sk->pk.seed, &adrs, PK_fors);


    ht_sign(PK_fors, sk->seed, sk->pk.seed, idx_tree, idx_leaf, sig_tmp);

}