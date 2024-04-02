#include <string.h>

#include "slh_sign.h"
#include "slh_hash.h"
#include "random.h"


// Algorithm 6
/**
 * @brief Generate a WOTS+ signature on an n-byte message
 * 
 * @param M Pointer to the message. Must be n bytes long
 * @param sk_seed Pointer to the secret key seed
 * @param pk_seed Pointer to the public key seed
 * @param adrs Pointer to the address
 * @param sig_out Pointer to array to store the generated WOTS+ signature. Must be (n * len) bytes long.
*/
void wots_sign(const char* m, const char* sk_seed, const char* pk_seed, ADRS* adrs, char* sig_out){
    uint64_t csum = 0;

    // Message 'm' is converted into base 'w' representation and stored in 'msg'
    uint16_t msg[SLH_PARAM_len];
    base_2b(m, SLH_PARAM_n, SLH_PARAM_lgw, SLH_PARAM_len1, msg);
    
    // Compute checksum by iterating over each character in 'msg'
    for (uint8_t i = 0; i < SLH_PARAM_len1; i++) {
        csum += (SLH_PARAM_w - 1) - (uint64_t)(msg[i]);
    }
    
    csum <<= ((8 - ((SLH_PARAM_len2 * SLH_PARAM_lgw) % 8)) % 8);  // Checksum is left-shifted to fit into bytes
    
    uint8_t csum_bytes[CSUM_BYTES];
    toByte(csum, csum_bytes, CSUM_BYTES);  // Convert checksum into a byte array
    

    base_2b(csum_bytes, CSUM_BYTES, SLH_PARAM_lgw, SLH_PARAM_len2, msg + SLH_PARAM_len1);  // Convert csum to base 'w'

    
    ADRS skADRS;
    memcpy(&skADRS, adrs, sizeof(ADRS));

    setTypeAndClear(&skADRS, WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(adrs));

    uint8_t sk[SLH_PARAM_n];
    //char* sig_out_tmp = sig_out;
    for (uint8_t i = 0; i < SLH_PARAM_len; i++) {  // Loop generates signature for each segment of msg
        setChainAddress(&skADRS, i);                // Sets chain address in ADRS structure for each segment

        PRF(pk_seed, sk_seed, &skADRS, sk);   // PRF is applied to the seed and ADFS structure to generate secret key value 'sk'
        
        setChainAddress(adrs, i);             // Set chain address for signature output

        chain(sk, 0, msg[i], pk_seed, adrs, sig_out);   // Computes hash chain for the signature

        // #if DEBUG_ENABLED
        //     printf("WOTS+ Signature: For Loop, i = %d\n", i);
        //     printf("WOTS+ Signature: sk = ");
        //     for (int j = 0; j < SLH_PARAM_n; j++){
        //         printf("%u, ", (unsigned char)sk[j]);
        //     }
        //     printf("\n");

        //     printf("WOTS+ Signature: msg[i] = %u\n", msg[i]);

        //     printf("WOTS+ Signature: sig_out = ");
        //     for (int j = 0; j < SLH_PARAM_n; j++){
        //         printf("%u, ", (unsigned char)sig_out[j]);
        //     }

        //     printf("\n\n");
        // #endif
        
        sig_out += SLH_PARAM_n;            // Move pointer to the next segment of the signature
    }
}



// Algorithm 9
/**
 * @brief Generate an XMSS signature
 * 
 * @param m Pointer to the message. Must be n bytes long
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long
 * @param idx Index of the WOTS+ node within the XMSS tree
 * @param pk_seed Pointer to the public key seed. Must be n bytes long
 * @param adrs Pointer to the address
 * @param sig_out Pointer to the array to store the generated XMSS signature. Must be XMSS_SIG_LEN bytes long.
*/
void xmss_sign(const char *m, const char *sk_seed, uint32_t idx, const char *pk_seed, ADRS *adrs, char *sig_out) {

    char *auth = sig_out + (SLH_PARAM_n * SLH_PARAM_len);
    
    uint32_t k;
    for (uint32_t j = 0; j < SLH_PARAM_hprime; j++) {
        k = (idx >> j) ^ 1;
        xmss_node(sk_seed, k, j, pk_seed, adrs, auth + (j * SLH_PARAM_n));
    }

    setTypeAndClear(adrs, WOTS_HASH);
    setKeyPairAddress(adrs, idx);
    wots_sign(m, sk_seed, pk_seed, adrs, sig_out);
}



// Algorithm 11
/**
 * @brief Generate a hypertree signature
 * 
 * @param m Pointer to the message. Must be n bytes long.
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param idx_tree Index of the XMSS tree at the lowest hypertree level. Must be less 2^(h - hprime).
 * @param idx_leaf Index of the WOTS+ key within the XMSS tree. Must be less than 2^hprime.
 * @param sig_out Pointer to the array to store the generated hypertree signature. Must be HT_SIG_LEN bytes long.
*/
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

    //char sig_ht [HT_SIG_LEN] = {0};
    char* sig_tmp = sig_out;

    xmss_sign(m, sk_seed, idx_leaf, pk_seed, &adrs, sig_tmp);

    char root[SLH_PARAM_n];
    xmss_PKFromSig(idx_leaf, sig_tmp, m, pk_seed, &adrs, root);
    sig_tmp += XMSS_SIG_LEN;

    // #if DEBUG_ENABLED
    //     printf("xmss_pkFromSig: root = ");
    //     for (int j = 0; j < SLH_PARAM_n; j++){
    //         printf("%u ", (unsigned char)root[j]);
    //     }
    //     printf("\n\n");
    // #endif

    for(uint8_t j = 1; j < SLH_PARAM_d; j++){

        idx_leaf = idx_tree & HPRIME_LSB_MASK;
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



// Algorithm 13
/**
 * @brief Generating FORS Secret Values
 * 
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param idx Index of the secret key. TODO
 * @param fors_sk Pointer to the array to store the generated FORS private-key value. Must be n bytes long.
*/
void fors_SKgen(const char* sk_seed, const char* pk_seed, const ADRS* adrs, uint32_t idx, char* fors_sk){
    ADRS skADRS;
    memcpy(&skADRS, adrs, sizeof(ADRS));
    setTypeAndClear(&skADRS, FORS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(adrs));
    setTreeIndex(&skADRS, idx);
    PRF(pk_seed, sk_seed, &skADRS, fors_sk);
}



// Algorithm 14
/**
 * @brief Compute the root of a Merkle subtree of FORS public values.
 * 
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param i Target node index
 * @param z Target node height
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param node Pointer to the array to store the generated node. Must be n bytes long.
 * 
 * @return char* node pointer or NULL if z > a or i ≥ k * 2 ^ (a − z)
*/
char* fors_node(const char* sk_seed, uint32_t i, uint32_t z, const char* pk_seed, ADRS* adrs, char* node){
    if ((z > SLH_PARAM_a) || (i >= SLH_PARAM_k * (1 << (SLH_PARAM_a - z)))) {
        return NULL;
    }
    
    if (z == 0) {
        char sk[SLH_PARAM_n];

        fors_SKgen(sk_seed, pk_seed, adrs, i, sk);  // Generate the secret key part for the leaf node
        
        // Generate public key value from secret key (assuming F modifies node in-place)
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, i);
        F(pk_seed, adrs, sk, node);

    } else {
        char lrnode[SLH_PARAM_n + SLH_PARAM_n]; // Buffer to hold the concatenation of lnode and rnode
        char *lnode = lrnode;
        char *rnode = lrnode + SLH_PARAM_n;
        

        // Recursively compute the left child node
        fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs, lnode);
        
        // Recursively compute the right child node
        fors_node(sk_seed, (2 * i) + 1, z - 1, pk_seed, adrs, rnode);

        // Prepare ADRS for the parent node computation
        setTreeHeight(adrs, z);
        setTreeIndex(adrs, i);

        // Hash the concatenated array and store the result in 'node'
        H(pk_seed, adrs, lrnode, node); // MD REVISIT: this might need to change based on how H is implemented/it's parameters
    }
    
    return node;
}



// Algorithm 15
/**
 * @brief Generate a FORS public key
 * 
 * @param md Pointer to the message digest. Must be ceil((k * a) / 8) bytes long.
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param pk_out Pointer to the array to store the generated FORS signature. Must fit FORS_SIG_LEN bytes.
*/
void fors_sign(const char* md, const char* sk_seed, const char* pk_seed, ADRS* adrs, char* sig_out){

    char* sig_fors = sig_out;

    uint16_t indices[SLH_PARAM_k];
    base_2b(md, SLH_SIGN_MD_LEN, SLH_PARAM_a, SLH_PARAM_k, indices);


    uint16_t s;

    for (uint8_t i = 0; i < SLH_PARAM_k; i++) {
        fors_SKgen(sk_seed, pk_seed, adrs, (i << SLH_PARAM_a) + ((uint32_t)(indices[i])), sig_fors);      // TODO NK: are we reading indices[i] correctly here?
        sig_fors += SLH_PARAM_n;

        for (uint8_t j = 0; j < SLH_PARAM_a; j++) {
            s = (indices[i] >> j) ^ 1;
            fors_node(sk_seed, ((i << (SLH_PARAM_a - j)) + s), j, pk_seed, adrs, sig_fors);
            sig_fors += SLH_PARAM_n;
        }
    }
}



void slh_sign(const char* msg, uint64_t msg_len, const SK* sk, char* sig){
    ADRS adrs = {0};

    char randByte;
    #if DEBUG_ENABLED
        printf("No Randomiztion for debugging\n");
        randByte = 0;
    #else
        randBytes(&randByte, 1);
    #endif

    const char *opt_rand;
    char new_rand[SLH_PARAM_n];

    if (randByte > 127){
        randBytes(new_rand, SLH_PARAM_n);
        opt_rand = new_rand;
    } else {
        opt_rand = sk->pk.seed;
    }

    char* sig_tmp = sig;

    // Store randomizer at the beginning of the signature
    PRF_msg(sk->prf, opt_rand, msg, msg_len, sig_tmp);      //32bytes
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
    uint64_t idx_tree = toInt(tmp_idx_tree, SLH_SIGN_TMPIDXTREE_LEN);
    idx_tree = idx_tree & SLH_SIGN_TREE_LSB_MASK;

    // Interpret it as a big-endian integer, and take the modulo.
    uint16_t idx_leaf = toInt(tmp_idx_leaf, SLH_SIGN_TMPIDXLEAF_LEN);
    idx_leaf = idx_leaf & SLH_SIGN_LEAF_LSB_MASK;

    setTreeAddress(&adrs, idx_tree);
    setTypeAndClear(&adrs, FORS_TREE);
    setKeyPairAddress(&adrs, idx_leaf);


    fors_sign(md, sk->seed, sk->pk.seed, &adrs, sig_tmp);       //11200 bytes

    // Get FORS Key
    char PK_fors[SLH_PARAM_n];
    fors_pkFromSig(sig_tmp, md, sk->pk.seed, &adrs, PK_fors);
    sig_tmp += FORS_SIG_LEN;

    ht_sign(PK_fors, sk->seed, sk->pk.seed, idx_tree, idx_leaf, sig_tmp);       //38,624 bytes

}