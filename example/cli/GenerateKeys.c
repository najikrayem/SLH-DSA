#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "slh_keygen.h"

int main(int argc, char *argv[]) {

    // Check if all two arguments are provided
    if (argc != 3) {
        printf("Usage: %s <secret_key_output_path> <public_key_output_path>\n", argv[0]);
        return 1;
    }

    char *privateKeyPath = argv[1];
    char *publicKeyPath = argv[2];

    // Open private key file for writing
    FILE *privateKeyFile = fopen(privateKeyPath, "w");
    if (privateKeyFile == NULL) {
        printf("Failed to open private key file\n");
        return 1;
    }

    // Open public key file for writing
    FILE *publicKeyFile = fopen(publicKeyPath, "w");
    if (publicKeyFile == NULL) {
        printf("Failed to open public key file\n");
        fclose(privateKeyFile); // Close the previously opened private key file
        return 1;
    }

    // Generate the keys
    PK pk;
    SK sk;
    slh_keygen(&sk, &pk);

    // Write to private key file
    fwrite(&sk, sizeof(SK), 1, privateKeyFile);

    // Write to public key file
    fwrite(&pk, sizeof(PK), 1, publicKeyFile);

    // Close the files
    fclose(privateKeyFile);
    fclose(publicKeyFile);
}