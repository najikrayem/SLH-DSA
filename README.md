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