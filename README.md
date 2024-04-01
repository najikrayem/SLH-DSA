# RTOS SLH-DSA

## Project Directory Structure
- `example\`: Example programs for the SLH-DSA implementations.
- `example\qnx_ifs_verify\`: Example that verifies QNX IFS images before mounting them.
- `slh-dsa\`: SLH-DSA implementation.
- `slh-dsa\armv8`: ARMv8 Optimized implementation.
- `slh-dsa\armv8\SHAKE256`: SHAKE256 ARMv8 optimized implementation.
- `slh-dsa\ref`: Reference C implementation.
- `slh-dsa\ref\SHAKE256`: SHAKE256 reference implementation.
- `test\`: Tests for the SLH-DSA implementations.

## References
- FIPS 205: [Stateless Hash-Based Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.ipd.pdf)
- FIPS 202: [SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

## Functions Verified Using GDB
- [x] slh_verify
- [x] slh_sign
- [ ] slh_keygen
- [x] getR
- [x] getSIG_FORS
- [x] getSIG_HT
- [x] Toint
- [x] setTreeAddress
- [x] setTypeAndClear
- [x] setKeyPairAddress
- [x] fors_pkFromSig
- [x] ht_verify
- [ ] randBytes
- [ ] fors_sign
- [ ] ht_sign
- [x] xmss_sign
- [ ] xmss_PKFromSig
- [x] xmss_node
- [x] wots_PKgen
- [x] setTreeHeight
- [x] setTreeIndex
- [x] H
- [x] getXMSSSignature
- [x] getWOTSSig
- [x] getXMSSAUTH
- [ ] wots_PKFromSig
- [x] getTreeIndex
- [ ] H_split
- [ ] base_2b
- [ ] toBytes
- [ ] setChainAddress
- [ ] setHashAddress
- [ ] getSK
- [x] getAUTH
- [ ] fors_SKgen


- [ ] F
- [ ] wots_sign
- [ ] PRF_msg
- [ ] H_msg
- [ ] chain
- [ ] getKeyPairAddress
- [ ] setLayerAddress
- [ ] PRF


# Checked
- [x] wots_PKFromSig
- [x] chain
- [x] T_len
- [x] All hash functions
- [x] fors_sign
- [x] xmss_PKFromSig
- [x] fors_SKgen
- [x] base_2b
- [x] toBytes

# Passing unit tests
- [x] BE32
- [x] BE64
- [x] toInt
- [x] ADRS
- [x] setLayerAddress
- [x] setKeyPairAddress
- [x] getKeyPairAddress
- [x] chain
- [x] H_msg
- [x] PRF
- [x] PRF_msg
- [x] F
- [x] wots_sign
- [x] fors_node
