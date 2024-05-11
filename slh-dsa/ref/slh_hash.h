#pragma once

#include <stdint.h>
#include "slh_config.h"
#include "slh_ds.h"


/**
 * @brief  Maps a (len*n)-byte message to an n-byte message.
 * 
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param m Pointer to the message. Must be len*n bytes long.
 * @param out Pointer to the array to store the generated hash. Must be n bytes long.
*/
void T_len(const char* pk_seed, const ADRS* adrs, const char* m, char* out);


/**
 * @brief Maps a (k*n)-byte message to an n-byte message.
 * 
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param m Pointer to the message. Must be k*n bytes long.
 * @param out Pointer to the array to store the generated hash. Must be n bytes long.
*/
void T_k(const char* pk_seed, const ADRS* adrs, const char* m, char* out);


/**
 * @brief Hash function takes in a 2n-byte input and outputs an n-byte hash.
 * 
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param m Pointer to the message. Must be 2n bytes long.
 * @param out Pointer to the array to store the generated hash. Must be n bytes long.
*/
void H(const char* pk_seed, const ADRS* adrs, const char* m, char* out);



/**
 * @brief Extremely similar to H, but the message is split into two n-byte messages.
 * to avoid the need for copying memory (particularly in the xmss_PKFromSig function)
 * 
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param m1 Pointer to the first message. Must be n bytes long.
 * @param m2 Pointer to the second message. Must be n bytes long.
 * @param out Pointer to the array to store the generated hash. Must be n bytes long
 * Can be equal to m1 or m2.
*/
void H_split(const char* pk_seed, const ADRS* adrs, const char* m1, const char* m2, char* out);




/**
 * @brief Used to generate the dirgest of the message.
 * SHAKE256(R ∥ PK.seed ∥ PK.root ∥ M,8m)
 * 
 * @param randomizer Pointer to the randomizer. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param pk_root Pointer to public key root. Must be n bytes long.
 * @param m Pointer to the message. Must be mlen bytes long.
 * @param mlen Length of the message.
 * @param out_hash Pointer to the array to store the generated hash. Must be m bytes long.
*/
void H_msg(const char* randomizer, const char* pk_seed, const char* pk_root, const char* m, uint64_t mlen, char* out_hash);


/**
 * @brief Psuedo-random function generate the randomizer for the randomized
 * hashing of the message.
 * 
 * @param sk_prf Pointer to the secret key for the PRF. Must be n bytes long.
 * @param opt_rand Pointer to the optional randomizer. Must be n bytes long.
 * @param m Pointer to the message. Must be mlen bytes long.
 * @param mlen Length of the message.
 * @param out_randomizer Pointer to the array to store the generated randomizer. Must be n bytes long.
 * 
*/
void PRF_msg(const char* sk_prf, const char* opt_rand, const char* m, uint64_t mlen, char* out_randomizer);


/**
 * @brief Hash function takes in an n-byte input and outputs an n-byte hash.
 * 
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param m Pointer to the message. Must be n bytes long.
 * @param out Pointer to the array to store the generated hash. Must be n bytes long.
*/
void F(const char* pk_seed, const ADRS* adrs, const char* m, char* out);


// /**
//  * @brief Very Similar to F, but it overwrites the input array with the hash.
//  * 
//  * @param pk_seed Pointer to the public key seed. Must be n bytes long.
//  * @param adrs Pointer to the address.
//  * @param m Pointer to the message. Must be n bytes long. It will be overwritten with the hash.
// */
// void F_inplace(const char* pk_seed, const ADRS* adrs, char* m);


/**
 * @brief Psuedo-random function that is used to generate the secret values in 
 * WOTS+ and FORS private keys.
 * 
 * @param sk_seed Pointer to the secret key seed. Must be n bytes long.
 * @param pk_seed Pointer to the public key seed. Must be n bytes long.
 * @param adrs Pointer to the address.
 * @param out Pointer to the array to store the generated PRF value. Must be n bytes long.
*/
void PRF(const char* pk_seed, const char* sk_seed, const ADRS* adrs, char* out);