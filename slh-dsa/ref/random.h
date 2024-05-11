#pragma once

#include <stdint.h>

/**
 * @brief Generate a random string of length len
 * 
 * @param str Pointer to the string to be filled with random characters.
*/
void randBytes(char* str, uint32_t len);
