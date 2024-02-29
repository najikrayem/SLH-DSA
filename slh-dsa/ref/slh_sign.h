#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "slh_common.h"


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

