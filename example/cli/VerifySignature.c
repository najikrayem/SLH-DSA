
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include "slh_verify.h"

int main(int argc, char *argv[]) {
    // Check if all three arguments are provided
    if (argc != 4) {
        printf("Usage: %s <public_key_file> <message_file> <signature_file>\n", argv[0]);
        return 1;
    }

    // Get the paths to the files
    char *publicKeyFile = argv[1];
    char *messageFile = argv[2];
    char *signatureFile = argv[3];

    // Attemp to mmap the public key file
    FILE *pkFile = fopen(publicKeyFile, "r");
    if (pkFile == NULL) {
        printf("Failed to open public key file\n");
        return 1;
    }
    PK *pk = mmap(NULL, sizeof(PK), PROT_READ, MAP_PRIVATE, fileno(pkFile), 0);

    if (pk == MAP_FAILED) {
        printf("Failed to mmap public key file: %s\n", strerror(errno));
        return 1;
    }


    // Attemp to mmap the message file
    FILE *msgFile = fopen(messageFile, "r");
    if (msgFile == NULL) {
        printf("Failed to open message file\n");
        return 1;
    }
    // Get size of the message file
    fseek(msgFile, 0, SEEK_END);
    size_t msgSize = ftell(msgFile);
    fseek(msgFile, 0, SEEK_SET);
    char *msg = mmap(NULL, msgSize, PROT_READ, MAP_PRIVATE, fileno(msgFile), 0);

    if (msg == MAP_FAILED) {
        printf("Failed to mmap message file: %s\n", strerror(errno));
        return 1;
    }


    // Attemp to mmap the input signature file
    FILE *sigFile = fopen(signatureFile, "r");
    if (sigFile == NULL) {
        printf("Failed to open signature file\n");
        return 1;
    }
    char *sig = mmap(NULL, SLH_PARAM_sig_bytes, PROT_READ, MAP_PRIVATE, fileno(sigFile), 0);

    if (sig == MAP_FAILED) {
        printf("Failed to mmap signature file: %s\n", strerror(errno));
        return 1;
    }

    // Verify the signature
    bool res = slh_verify(msg, msgSize, sig, pk);

    if (res) {
        printf("Signature is valid\n");
    } else {
        printf("Signature is invalid\n");
    }

    // Unmap the files
    munmap(pk, sizeof(PK));
    munmap(msg, msgSize);
    munmap(sig, SLH_PARAM_sig_bytes);

    return 0;
}