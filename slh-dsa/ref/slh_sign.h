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