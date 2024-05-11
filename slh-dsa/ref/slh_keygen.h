#pragma once

#include "slh_common.h"


// Algorithm 17
/**
 * @brief Generate an SLH-DSA key pair
 *
 * @param out_sk Pointer to the SecretKey struct to store the generated secret key. Typically 2 * n bytes long.
 * @param out_pk Pointer to the PublicKey struct to store the generated public key. Typically 4 * n bytes long.
*/
void slh_keygen(SK* out_sk, PK* out_pk);
