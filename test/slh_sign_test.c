#include "unity.h"
#include "slh_sign.h"
#include "slh_hash.h"

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

void test_function_wots_sign() {
    ADRS adrs = {0};
    
    char pk_zeros[SLH_PARAM_n] = {0};
    char sk_zeros[SLH_PARAM_n] = {0};    
    
    char signature1[SLH_PARAM_len * SLH_PARAM_n];
    char signature2[SLH_PARAM_len * SLH_PARAM_n];
    
    const unsigned char expected1[SLH_PARAM_n] = {
        0x40, 0xcf, 0x8d, 0x0b, 0xbd, 0x41, 0xe9, 0xd3,
        0xe0, 0x0a, 0x78, 0xf2, 0x54, 0x45, 0xd2, 0x42,
        0x0a, 0x56, 0xd0, 0x08, 0xf8, 0x75, 0x2d, 0x67,
        0xba, 0xd0, 0xbb, 0x6e, 0x7e, 0x20, 0xb0, 0x5e
    };
    
    const unsigned char expected2[SLH_PARAM_n] = {
        0x69, 0x74, 0x07, 0x93, 0x5e, 0x33, 0xf9, 0xa4,
        0xdc, 0xce, 0x48, 0x09, 0x4b, 0x1c, 0xfb, 0x9b,
        0x8c, 0xb6, 0x88, 0xa7, 0x27, 0x20, 0x1e, 0xd3,
        0x42, 0xac, 0x87, 0x41, 0x8e, 0x5e, 0x58, 0xf1
    };       
    
    // MD - adjusted this here and in the python version for Naji since it looks like he was trying to test it with byte arrays of 0s?
    wots_sign(m, sk_zeros, pk_zeros, &adrs, signature1);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected1, signature1, SLH_PARAM_n);
    
    wots_sign(m, sk_seed, pk_seed, &adrs, signature2);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected2, signature2, SLH_PARAM_n);
}

void test_function_xmss_sign() {
    uint32_t idx = 4;
    ADRS adrs = {0};
    char signature[XMSS_SIG_LEN]; 

    const unsigned char expected[SLH_PARAM_n] = {
        0x65, 0x32, 0xf9, 0x96, 0x46, 0x31, 0x32, 0xba,
        0x16, 0xdf, 0xef, 0xf1, 0x3f, 0x8d, 0xb6, 0x6d,
        0x78, 0xc7, 0xfd, 0x5f, 0xeb, 0xc8, 0xa3, 0x5c,
        0xd9, 0x92, 0x60, 0x56, 0x77, 0xd1, 0xba, 0x7a
    };

    xmss_sign(m, sk_seed, idx, pk_seed, &adrs, signature);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, signature, SLH_PARAM_n);
}

void test_function_fors_SKgen() {
    ADRS adrs = {0};
    uint32_t idx = 42;
    char fors_sk[SLH_PARAM_n];
     
    const unsigned char expected[SLH_PARAM_n] = {
        0xad, 0x4f, 0x79, 0xff, 0x75, 0xaa, 0x33, 0x9a,
        0x1e, 0x7d, 0x28, 0x41, 0x71, 0x1d, 0x30, 0xcc,
        0xe8, 0xa3, 0xea, 0xb9, 0xbb, 0x18, 0x5f, 0x71,
        0x09, 0x2c, 0x9c, 0xc9, 0xae, 0x84, 0xdf, 0x64
    };     
     
    fors_SKgen(sk_seed, pk_seed, &adrs, idx, fors_sk);
    
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, fors_sk, SLH_PARAM_n);
}

void test_function_fors_node() {
    ADRS adrs = {0};  

    char leaf_node[SLH_PARAM_n * 2];
    char intermediate_node[SLH_PARAM_n * 2];

    const unsigned char expected_leaf[SLH_PARAM_n] = {
        0xca, 0x3f, 0x21, 0x41, 0x22, 0x3e, 0x96, 0x16,
        0x00, 0x62, 0xe1, 0xa9, 0xf6, 0xf4, 0x68, 0x35,
        0x17, 0x3c, 0x04, 0x19, 0x13, 0x6d, 0xef, 0x68,
        0xee, 0x7b, 0x5c, 0x30, 0x32, 0x3e, 0xc8, 0xcc
    };    

    const unsigned char expected_intermediate[SLH_PARAM_n] = {
        0xb0, 0x42, 0x7f, 0xfb, 0xd6, 0x47, 0x24, 0x5f,
        0xd7, 0x40, 0xdc, 0xbd, 0x29, 0x8c, 0x11, 0xfe,
        0x08, 0x4a, 0x75, 0x1a, 0x34, 0x15, 0x03, 0x68,
        0xc2, 0x02, 0xfa, 0x68, 0x95, 0x93, 0xf5, 0xf0
    };    
    
    // Test for a leaf node
    fors_node(sk_seed, 0, 0, pk_seed, &adrs, leaf_node);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_leaf, leaf_node, SLH_PARAM_n);

    // Test for an intermediate node
    fors_node(sk_seed, 0, 1, pk_seed, &adrs, intermediate_node);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_intermediate, intermediate_node, SLH_PARAM_n);

}

// MD REVISIT
void test_function_fors_sign() {
    unsigned char out_hash[SLH_PARAM_n];

    H_msg(randomizer, pk_seed, pk_root, m, SLH_PARAM_n, out_hash);

    // matches
    printf("FORS out_hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", out_hash[i]);
    }
    
    printf("\n");

    ADRS adrs = {0};  
    unsigned char sig_fors[FORS_SIG_LEN];

    fors_sign(out_hash, sk_seed, pk_seed, &adrs, sig_fors);

    // this part doesn't match python implementation
    printf("FORS sig_fors: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_fors[i]);
    }
    printf("\n");
}

void test_function_ht_sign() {
    uint64_t i_tree = 2;
    uint32_t i_leaf = 3;
    char sig_ht[HT_SIG_LEN];

    ht_sign(m, sk_seed, pk_seed, i_tree, i_leaf, sig_ht);
    
    const unsigned char expected[SLH_PARAM_n] = {
        0x86, 0xb0, 0xac, 0xee, 0x8b, 0x56, 0x0d, 0xbe,
        0xbc, 0x1e, 0xc7, 0xcb, 0xc7, 0xf4, 0x0f, 0x8f,
        0xd3, 0x07, 0x97, 0x53, 0x46, 0x3f, 0xa5, 0xf9,
        0x55, 0x05, 0xaa, 0xf4, 0x6f, 0x9b, 0x21, 0xe7
    };    
    
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, sig_ht, SLH_PARAM_n);
}


int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_function_wots_sign); 
    RUN_TEST(test_function_xmss_sign);
    RUN_TEST(test_function_fors_SKgen);
    RUN_TEST(test_function_fors_node);
    //test_function_fors_sign();
    RUN_TEST(test_function_ht_sign);
    
    return UNITY_END();
}
