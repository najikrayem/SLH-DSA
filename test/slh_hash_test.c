#include "unity.h"
#include "slh_sign.h"
#include "slh_hash.h"
#include <string.h>

char m[SLH_PARAM_n] = "abcdefghijklmnopqrstuvwxyz123456";
char randomizer[SLH_PARAM_n] = "123456789123456789abcdefabcdefab";
char pk_root[PK_ROOT_BYTES] = "fedcba9876543210987654321abcdefg";
char sk_prf[SK_PRF_BYTES] = "zlmnopqrstuv12345678901234567890";
char opt_rand[SLH_PARAM_n] = "qrstuvwxyz9876543210012345678900";

char pk_seed[PK_SEED_BYTES] = {
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

char sk_seed[SK_SEED_BYTES] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};


void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void test_function_H_msg() {
    char out[SLH_PARAM_m];
    
    H_msg(randomizer, pk_seed, pk_root, m, SLH_PARAM_n, out);

    const unsigned char expected[SLH_PARAM_n] = {
        0xa2, 0x9f, 0x5b, 0x8c, 0xa2, 0xbd, 0x59, 0x07,
        0x40, 0x95, 0x98, 0x68, 0xf1, 0x03, 0xd2, 0xe1,
        0xfa, 0x7a, 0xf6, 0x88, 0x5c, 0xf6, 0xe5, 0x9a,
        0x4b, 0xfc, 0x19, 0x45, 0x83, 0xf4, 0xd2, 0xf4
    }; 
    
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, out, SLH_PARAM_n);
}

void test_function_PRF() {
    ADRS adrs = {0};
    char out[SLH_PARAM_n];

    PRF(pk_seed, sk_seed, &adrs, out);

    const unsigned char expected[SLH_PARAM_n] = {
        0xd2, 0xd1, 0x93, 0x1b, 0xaf, 0xea, 0xeb, 0x7e,
        0xe7, 0xc9, 0xf2, 0xa4, 0xe0, 0xb1, 0xb4, 0x84,
        0x50, 0x0c, 0xec, 0x80, 0xf8, 0xbb, 0xa8, 0x65,
        0xde, 0x56, 0xe7, 0x20, 0xdf, 0xfb, 0x50, 0x0e
    };
    
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, out, SLH_PARAM_n);
}


void test_function_PRF_msg() {
    char out[SLH_PARAM_n];

    const unsigned char expected[SLH_PARAM_n] = {
        0xa8, 0x65, 0x47, 0x59, 0xf2, 0xbc, 0x16, 0xdd,
        0x4e, 0x6b, 0xec, 0xe7, 0xca, 0x84, 0xbb, 0x65,
        0x64, 0x04, 0x02, 0xc6, 0xd3, 0xdb, 0xbe, 0x0d,
        0x7c, 0xfa, 0x72, 0x2c, 0xb6, 0x8e, 0x87, 0xb8
    };

    PRF_msg(sk_prf, opt_rand, m, SLH_PARAM_n, out);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, out, SLH_PARAM_n);
}

void test_function_F(){
    ADRS adrs = {0}; 
    char out[SLH_PARAM_n] = {0};

    const unsigned char expected[SLH_PARAM_n] = {
        0xdb, 0xd0, 0x67, 0xca, 0x87, 0xfe, 0xee, 0x89,
        0x20, 0x76, 0xd7, 0x3f, 0xf4, 0x10, 0x4c, 0xb8,
        0xd8, 0x83, 0x0a, 0xa1, 0xec, 0x9a, 0x7d, 0x43,
        0x37, 0x16, 0xa2, 0xf3, 0x6b, 0x6d, 0xcd, 0x30
    };

    F(pk_seed, &adrs, m, out);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, out, SLH_PARAM_n);
}


int main(void) {
    UNITY_BEGIN();

    //RUN_TEST(test_function_H_msg);
    RUN_TEST(test_function_PRF);
    RUN_TEST(test_function_PRF_msg);
    RUN_TEST(test_function_F);

    return UNITY_END();
}
