#pragma once


#include <stdint.h>
#include <stdbool.h>

#include "slh_config.h"
#include "slh_ds.h"



// These two functions swap the byte order of a 32-bit or 64-bit integer.
// We don't know how well optimized the built-in functions are, so we use
// inline assembly for ARM64 and the built-in functions for other architectures.
static inline uint32_t byteswap32(uint32_t x) {
    #ifdef __aarch64__
        __asm__("REV %w0, %w0" : "+r" (x));
    #else
        x = __builtin_bswap32(x);
    #endif
    return x;
}
static inline uint64_t byteswap64(uint64_t x) {
    #ifdef __aarch64__
        __asm__("REV %x0, %x0" : "+r" (x));
    #else
        x = __builtin_bswap64(x);
    #endif
    return x;
}
// Macro to convert to big-endian iff the system is little-endian.
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define BE32(x) (byteswap32(x))
    #define BE64(x) (byteswap64(x))
#else
    #define BE32(x) (x)
    #define BE64(x) (x)
#endif


// Address struct helper functions
static inline void setTreeAddress(ADRS* adrs, uint64_t idx_tree){
    adrs->address = BE64(idx_tree);}

static inline void setLayerAddress(ADRS* adrs, uint8_t layer){
    adrs->layer = layer;}

static inline void setTypeAndClear(ADRS* adrs, AddressType type){
    adrs->type = (uint8_t)type;
    adrs->w1 = 0;
    adrs->w2 = 0;
    adrs->w3 = 0;}

static inline void setKeyPairAddress(ADRS* adrs, uint32_t idx_leaf){
    #if DATA_CHECKS_ENABLED
        if (adrs->type == TREE){
            // TODO THROW ERROR
        }
    #endif
    adrs->w1 = BE32(idx_leaf);}

static inline uint32_t getKeyPairAddress(const ADRS* adrs){
    return BE32(adrs->w1);}

static inline void setHashAddress(ADRS* adrs, uint32_t idx_leaf){
    #if DATA_CHECKS_ENABLED
        if (adrs->type != WOTS_HASH){
            // TODO THROW ERROR
        }
    #endif
    adrs->w3 = BE32(idx_leaf);}

static inline void setTreeIndex(ADRS* adrs, uint32_t idx_tree){
    adrs->w3 = BE32(idx_tree);}

static inline uint32_t getTreeIndex(const ADRS* adrs){
    return BE32(adrs->w3);}

static inline void setChainAddress(ADRS* adrs, uint32_t idx_chain){
    #if DATA_CHECKS_ENABLED
        if ((adrs->type != WOTS_HASH) || (adrs->type != WOTS_PRF)){
            // TODO THROW ERROR
        }
    #endif
    adrs->w2 = BE32(idx_chain);}

static inline void setTreeHeight(ADRS* adrs, uint32_t tree_height){
    adrs->w2 = BE32(tree_height);}





/**
 * @brief Get a pointer to the WOTS signature in the XMSS signature. The WOTS
 * signature is stored at the beginning of the XMSS signature, specifically at
 * [0 : len * n]
 * 
 * @param sig_xmss Pointer to the XMSS signature.
*/
static inline const char* getWOTSSig(const char* sig_xmss){
    return sig_xmss;}


/**
 * @brief Get a pointer to the auth path within the XMSS signature. It is stored
 * after the WOTS signature, specifically at [len * n : (len + hprime) * n]
 * 
 * @param sig_xmss Pointer to the XMSS signature.
*/
static inline const char* getXMSSAUTH(const char* sig_xmss){
    return sig_xmss + (SLH_PARAM_len * SLH_PARAM_n);}


/**
 * @brief Get a pointer to the private key value of tree at index 0 <= idx < k.
 * SK is n-bytes long, and there are k of them along with a*n-bytes long 
 * AUTHs in the FORS signature.
*/
static inline const char* getSK (const char* fors_sig, uint8_t idx){
    return fors_sig + (idx * (SLH_PARAM_n * (SLH_PARAM_a + 1)));}


/**
 * @brief TODO
*/
static inline const char* getAUTH(const char* fors_sig, uint8_t idx){
    return fors_sig + (((idx * (SLH_PARAM_a + 1)) + 1) * SLH_PARAM_n);}


// Algorithm 1
/**
 * @brief Convert a byte array to an integer
 * 
 * @param x pointer to the byte string. Must be n bytes long.
 * @param n Length of the input
 * 
 * @return uint64_t The integer value of the byte string
 * 
*/
uint64_t toInt(const uint8_t *X, uint8_t n);



// Algorithm 2
/**
 * @brief Convert an integer to a byte string.
 * 
 * @param x integer to be converted.
 * @param out Pointer to the output array that hold the byte string. Must be n bytes long.
 * @param out_len Length of the output
 * 
*/
void toByte(uint64_t x, char* out, uint8_t out_len);



// Algorithm 3
/**
 * @brief Compute the base 2^b representation of X.
 * 
 * @param x Pointer to byte string 
 * @param in_len Length of the input. Must be at least ceil(out_len*b/8) bytes long. CURRENTLY UNUSED
 * @param b Base
 * @param out_len Length of the output
 * @param out Pointer to the output of length out_len
*/
void base_2b(const char *x, uint64_t in_len, uint8_t b, uint8_t out_len, uint16_t *out);



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
char* chain(const char* x, uint32_t i, uint32_t s, const char* pk_seed, ADRS* adrs, char* out);



// Algorithm 5
/**
 * @brief Generate a WOTS+ public key
 * 
 * @param sk_seed Pointer to the secret key seed
 * @param pk_seed Pointer to the public key seed
 * @param adrs Pointer to the address
 * @param pk_out Pointer to array to store the generated WOTS+ public key. Must be n bytes long
*/
void wots_PKgen(const char* sk_seed, const char* pk_seed, ADRS* adrs, char* pk_out);



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



// Algorithm 16
/**
 * @brief Compute a FORS public key from a FORS signature
 * 
 * @param sig_fors Pointer to the FORS signature. Must be FORS_SIG_LEN bytes long.
 * @param md Pointer to the message digest. Must be ceil((k * a) / 8) bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param pk_out Pointer to the array to store the computed FORS public key. Must be n bytes long.
*/
void fors_pkFromSig(const char* sig_fors, const char* md, const char* pk_seed, ADRS* adrs, char* pk_out);
