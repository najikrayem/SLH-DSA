#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "slh_common.h"

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
void xmss_sign(const char *m, const char *sk_seed, uint32_t idx, const char *pk_seed, ADRS *adrs, char *sig_out);

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
void fors_SKgen(const char* sk_seed, const char* pk_seed, const ADRS* adrs, uint32_t idx, char* fors_sk);

// Algorithm 18
/**
 * @brief Signs a message.
 * 
 * @param msg Message to sign.
 * @param msg_len Message length in bytes.
 * @param sk Secret key pointer.
 * @param sig Pointer to output signature. Must be SLH_PARAM_sig_bytes long.
 */
void slh_sign(const char* msg, uint64_t msg_len, const SK* sk, char* sig);

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
void ht_sign(const char* m, const char* sk_seed, const char* pk_seed, uint64_t idx_tree, uint32_t idx_leaf, char* sig_out);

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
char* fors_node(const char* sk_seed, uint32_t i, uint32_t z, const char* pk_seed, ADRS* adrs, char* node);


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
void fors_sign(const char* md, const char* sk_seed, const char* pk_seed, ADRS* adrs, char* sig_out);
