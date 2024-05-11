# RTOS SLH-DSA

## DISCLAIMER OF WARRANTY

The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings
in the software.


## Overview

The rise of quantum computing is fast approaching, bringing with it significant challenges to the security of systems that depend on traditional cryptography methods. Despite ongoing efforts to develop and standardize PQC algorithms, the slow and expensive update processes in embedded systems pose obstacles to their timely adoption. These systems often need months or even years to update due to the nature of their uses, in addition to the substantial costs involved in deploying updates, whether by dispatching field personnel or using over-the-air (OTA) networks. As a result, the sluggish update cycles may expose many critical systems to quantum computing threats. Therefore, quickly updating existing systems and incorporating PQC into new designs is vital. We aim to implement the SLH-DSA algorithm, offering a variant specially optimized for the Armv8-A platform, in accordance with the standards specified by NIST in the FIPS 202, and 205 publications.


## Project Directory Structure
``` 
.
├── example                             # Example programs for the SLH-DSA implementations.
|   ├── cli
|   |   ├── GenerateKeys.c              # Simple CLI program to generate SLH-DSA keys.
|   |   ├── SignMessahe.c               # Simple CLI program to sign a message using SLH-DSA.
|   |   └── VerifySignature.c           # Simple CLI program to verify a message using SLH-DSA.
│   └── qnx_ifs_verify_mount            # Example program that verifies QNX image file-systems before mounting them.  
├── slh-dsa
│       ├── armv8
│       │   └── SHAKE256                # ARMv8 assembly optimized KECCAK1600 implementation.
│       └── ref                         # Reference C implementation of the SLH-DSA.
│           └── SHAKE256                # Reference C implementation of the FIPS 202. With minor modifications borrowed from the reference implementation of the SPHINCS+.
├── test
│   ├──                                 # TODO
└── README.md
```

## References
- FIPS 205: [Stateless Hash-Based Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.ipd.pdf)
- FIPS 202: [SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
