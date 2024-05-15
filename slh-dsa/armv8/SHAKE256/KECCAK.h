
#pragma once

#include <stdint.h>
#include <stddef.h>

void KeccakF1600_StatePermute_ARMv8A(uint64_t *ptr);

void Keccak_Inc_Absorb_ARMv8A(uint64_t *s_inc, const uint8_t *m, uint64_t mlen);