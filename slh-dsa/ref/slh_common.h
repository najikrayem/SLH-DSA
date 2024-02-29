#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "slh_config.h"


// PublicKey struct
typedef struct PublicKey{
    char root[SLH_PARAM_n];
    char seed[SLH_PARAM_n];
} PK;


// SecretKey struct
typedef struct SecretKey{
    char seed[SLH_PARAM_n];
    char prf [SLH_PARAM_n];
    PK pk;
} SK;


// Address struct
typedef struct Address{
    // NK TODO
} ADRS;


// NK TODO: ADRS struct function signatures are not yet complete
void setHashAddress(void*);
void setTypeAndClear(void*);
void setKeyPairAddress(void*);
void getKeyPairAddress(void*);
void setChainAddress(void*);
void setTreeHeight(void*);
void setTreeIndex(void*);
void getTreeIndex(void*);
void setTreeAddress(void*);
void setLayerAddress(void*);


// NK TODO: SIG_XMSS function signatures are not yet complete
void getWOTSSig(void*);
void getXMSSAUTH(void*);


// NK TODO: SIG_HT function signatures are not yet complete
void getXMSSSignature(void*);
void getXMSSAUTH(void*);


// NK TODO: Hash functions signatures are not yet complete
void PRF_msg(void*);
void H_msg(void*);
void PRF(void*);
void T_l(void*);
void H(void*);
void F(void*);


// Algorithm 1
/**
 * @brief Convert a byte array to an integer
 * 
 * @param x pointer to the byte string. Must be n bytes long.
 * @param out Pointer to the output array that hold the "integer". Must be n bytes long.
 * 
*/
void toInt(const char* x, char* length);



// Algorithm 2
/**
 * @brief Convert an integer to a byte string.
 * 
 * @param x "integer" to be converted. Array of n bytes.
 * @param out Pointer to the output array that hold the byte string. Must be n bytes long.
 * 
*/
void toByte(const char* x, char* out);



// Algorithm 3
/**
 * @brief Compute the base 2^b representation of X.
 * 
 * @param x Pointer to byte string 
 * @param in_len Length of the input. Must be at least ceil(out_len*b/8) bytes long
 * @param b Base
 * @param out_len Length of the output
 * @param out Pointer to the output of length out_len
*/
void base_2b(const char* x, uint64_t in_len, uint8_t b, uint64_t out_len, char* out);



// Algorithm 4
/**
 * @brief Chaining function used in WOTS+
 * 
 * @param x Pointer to the byte string. Must be n bytes long
 * @param i Index
 * @param s Steps
 * @param pk_seed Pointer to the public key. Only the seed is used
 * @param adrs Pointer to the address
 * @param out Pointer to the output byte string, must be n bytes long.
 * 
 * @return char* out pointer, or NULL if (i + s) ≥ w
 * 
 */
char* chain(const char* x, uint64_t i, uint64_t s, const char* pk_seed, ADRS* adrs, char* out);



// Algorithm 5
/**
 * @brief Generate a WOTS+ public key
 * 
 * @param sk_seed Pointer to the secret key seed
 * @param pk_seed Pointer to the public key seed
 * @param adrs Pointer to the address
 * @param pk_out Pointer to array to store the generated WOTS+ public key
*/
void wots_PKgen(const char* sk_seed, const char* pk_seed, ADRS* adrs, char* pk_out);



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
void wots_sign(const char* m, const char* sk_seed, const char* pk_seed, ADRS* adrs, char* sig_out);



// Algorithm 7
/**
 * @brief Compute a WOTS+ public key from a message and its signature
 * 
 * @param sig Pointer to the signature. Must be (n * len) bytes long
 * @param m Pointer to the message. Must be n bytes long
 * @param pk_seed Pointer to the public key seed. Must be n bytes long
 * @param adrs Pointer to the address
 * @param pk_out Pointer to array to store the generated WOTS+ public key. Must be n bytes long
*/
void wots_PKFromSig(const char* sig, const char* m, const char* pk_seed, ADRS* adrs, char* pk_out);



// Algorithm 8
/**
 * @brief Compute the root of a Merkle subtree of WOTS+ public keys
 * 
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long
 * @param i Target node index
 * @param z Target node height
 * @param pk_seed Pointer to the public key seed. Must be n bytes long
 * @param adrs Pointer to the address.
 * @param node Pointer to the array to store the generated node. Must be n bytes long.
 * 
 * @return char* node pointer or NULL if z > hprime or i ≥ 2^(hprime−z)
*/
char* xmss_node(const char* sk_seed, uint32_t i, uint32_t z, const char* pk_seed, ADRS* adrs, char* node);


// Algorithm 9
/**
 * @brief Generate an XMSS signature
 * 
 * @param m Pointer to the message. Must be n bytes long
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long
 * @param idx Index of the WOTS+ node within the XMSS tree
 * @param pk_seed Pointer to the public key seed. Must be n bytes long
 * @param adrs Pointer to the address
 * @param sig_out Pointer to the array to store the generated XMSS signature. Must be n*(hprime + len) bytes long.
*/
void xmss_sign(const char* m, const char* sk_seed, uint32_t idx, const char* pk_seed, ADRS* adrs, char* sig_out); 


// Algorithm 10
/**
 * @brief Compute an XMSS public key from an XMSS signature
 * 
 * @param idx Index of the WOTS+ node within the XMSS tree
 * @param sig_xmss Pointer to the XMSS signature. Must be n*(hprime + len) bytes long.
 * @param m Pointer to the message. Must be n bytes long
 * @param pk_seed Pointer to the public key seed. Must be n bytes long
 * @param adrs Pointer to the address
 * @param root_out Pointer to the array to store the root value of node[0]. Must be n bytes long.
*/
void xmss_PKFromSig(uint32_t idx, const char* sig_xmss, const char* m, const char* pk_seed, ADRS* adrs, char* root_out);



// Algorithm 11
/**
 * @brief Generate a hypertree signature
 * 
 * @param m Pointer to the message. Must be n bytes long.
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param idx_tree Index of the XMSS tree at the lowest hypertree level. Must be less 2^(h - hprime).
 * @param idx_leaf Index of the WOTS+ key within the XMSS tree. TODO
 * @param sig_out Pointer to the array to store the generated hypertree signature. Must be n*(h + d * len) bytes long.
*/
void ht_sign(const char* m, const char* sk_seed, const char* pk_seed, uint64_t idx_tree, uint64_t idx_leaf, char* sig_out);



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
bool ht_verify(const char* m, const char* sig_ht, const char* pk_seed, uint64_t idx_tree, uint64_t idx_leaf, const char* pk_root); 



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
void fors_SKgen(const char* sk_seed, const char* pk_seed, const ADRS* adrs, uint64_t idx, char* fors_sk); 



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
char* fors_node(const char* sk_seed, uint64_t i, uint64_t z, const char* pk_seed, ADRS* adrs, char* node);



// Algorithm 15
/**
 * @brief Generate a FORS public key
 * 
 * @param md Pointer to the message digest. Must be k * a bits long (not bytes).
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param pk_out Pointer to the array to store the generated FORS signature. Must be k * (n * (a + 1)) bytes long.
*/
void fors_sign(const char* md, const char* sk_seed, const char* pk_seed, const ADRS* adrs, char* sig_out);



// Algorithm 16
/**
 * @brief Compute a FORS public key from a FORS signature
 * 
 * @param sig_fors Pointer to the FORS signature. Must be k * (n * (a + 1)) bytes long.
 * @param md Pointer to the message digest. Must be k * a bits long (not bytes).
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param pk_out Pointer to the array to store the computed FORS public key. Must be n bytes long.
*/
void fors_pkFromSig(const char* sig_fors, const char* md, const char* pk_seed, ADRS* adrs, char* pk_out);

