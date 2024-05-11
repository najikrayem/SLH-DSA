#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#include "slh_sign.h"

int main(int argc, char *argv[]) {
    // Check if all three arguments are provided
    if (argc != 4) {
        printf("Usage: %s <secret_key_file> <message_file> <signature_file>\n", argv[0]);
        return 1;
    }

    // Get the paths to the files
    char *secretKeyFile = argv[1];
    char *messageFile = argv[2];
    char *signatureFile = argv[3];

    // Attemp to mmap the secret key file
    FILE *skFile = fopen(secretKeyFile, "r");
    if (skFile == NULL) {
        printf("Failed to open secret key file\n");
        return 1;
    }
    SK *sk = mmap(NULL, sizeof(SK), PROT_READ, MAP_PRIVATE, fileno(skFile), 0);

    if (sk == MAP_FAILED) {
        printf("Failed to mmap secret key file: %s\n", strerror(errno));
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


    // Attemp to mmap the out signature file
    FILE *sigFile = fopen(signatureFile, "w+");
    if (sigFile == NULL) {
        printf("Failed to open signature file\n");
        return 1;
    }

    // Set the file to the size we want it to be
    if (ftruncate(fileno(sigFile), SLH_PARAM_sig_bytes) == -1) {
        printf("Failed to set file size: %s\n", strerror(errno));
        return 1;
    }

    char *sig = mmap(NULL, SLH_PARAM_sig_bytes , PROT_WRITE, MAP_SHARED, fileno(sigFile), 0);

    if (sig == MAP_FAILED) {
        printf("Failed to mmap signature file: %s\n", strerror(errno));
        return 1;
    }


    // Sign the message
    slh_sign(msg, msgSize, sk, sig);

    // Unmap the files
    munmap(sk, sizeof(SK));
    munmap(msg, msgSize);
    munmap(sig, SLH_PARAM_sig_bytes);

    // Close the files
    fclose(skFile);
    fclose(msgFile);
    fclose(sigFile);


    return 0;
}