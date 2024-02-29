#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "slh_common.h"


// Algorithm 19
/**
 * @brief Verifies a signature.
 * 
 * @param msg Message to verify.
 * @param msg_len Message length.
 * @param sig Signature to verify. Must be SLH_PARAM_sig_bytes bytes long.
 * @param pk Pointer to public key.
 * 
 * @return True if the signature is valid, false otherwise.
 */
bool slh_verify(const char *msg, uint64_t msg_len, const char *sig, const PK *pk);