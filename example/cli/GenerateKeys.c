#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "slh_keygen.h"

int main(int argc, char *argv[]) {
    int option;

    char *privateKeyPath = NULL;
    char *publicKeyPath = NULL;

    // Parse command line arguments
    while ((option = getopt(argc, argv, "hp:s:")) != -1) {
        switch (option) {
            case 'h':
                printf(
                    "SLH DSA; Generate Public and Private Key.\n"
                    "\t-h\t\tShow this help message\n"
                    "\t-s\t\tSet the path to the secret key file\n"
                    "\t-p\t\tSet the path to the public key file\n");
                return 0;
            case 's':
                privateKeyPath = optarg;
                break;
            case 'p':
                publicKeyPath = optarg;
                break;
            default:
                printf("Invalid option\n");
                return 1;
        }
    }

    if (privateKeyPath == NULL || publicKeyPath == NULL) {
        printf("Both -s and -p options are mandatory\n");
        return 1;
    }

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


    // Close the files
    fclose(privateKeyFile);
    fclose(publicKeyFile);
}