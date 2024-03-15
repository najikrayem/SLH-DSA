#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

void randBytes(char* str, uint32_t len){
    int fd = open("/dev/random", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /dev/random, trying /dev/urandom");
    } else {
        ssize_t result = read(fd, str, len);
        if (result == -1) {
            perror("Failed to read from /dev/random, trying /dev/urandom");
            close(fd);
        }
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /dev/urandom, exiting.");
        exit(1);
    }
    ssize_t result = read(fd, str, len);
    if (result == -1) {
        perror("Failed to read from /dev/urandom, exiting.");
        close(fd);
        exit(1);
    }

    close(fd);
}