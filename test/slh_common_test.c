#include "unity.h"
#include "slh_common.h"

char m[SLH_PARAM_n] = "abcdefghijklmnopqrstuvwxyz123456";

char pk_seed[PK_SEED_BYTES] = {
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};


void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void test_function_BE32(void) {
    uint32_t x = 0x12345678;
    TEST_ASSERT_EQUAL_HEX32(0x78563412, BE32(x));

    x = 0xFFFFFFFF;
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, BE32(x));

    x = 0x00000000;
    TEST_ASSERT_EQUAL_HEX32(0x00000000, BE32(x));

    x = 0x00000001;
    TEST_ASSERT_EQUAL_HEX32(0x01000000, BE32(x));
}


void test_function_BE64(void) {
    uint64_t x = 0x123456789ABCDEF0;
    TEST_ASSERT_EQUAL_HEX64(0xF0DEBC9A78563412, BE64(x));

    x = 0xFFFFFFFFFFFFFFFF;
    TEST_ASSERT_EQUAL_HEX64(0xFFFFFFFFFFFFFFFF, BE64(x));

    x = 0x0000000000000000;
    TEST_ASSERT_EQUAL_HEX64(0x0000000000000000, BE64(x));

    x = 0x0000000000000001;
    TEST_ASSERT_EQUAL_HEX64(0x0100000000000000, BE64(x));
}


void test_function_toInt(void) {
    uint8_t x[4] = {0x12, 0x34, 0x56, 0x78};
    uint32_t y;
    y = toInt(x, sizeof(uint32_t));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, y);


    y = toInt(x, 2);
    TEST_ASSERT_EQUAL_HEX32(0x1234, y);


    uint8_t z[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    uint64_t w;
    w = toInt(z, sizeof(uint64_t));
    TEST_ASSERT_EQUAL_HEX64(0x123456789ABCDEF0, w);

    w = toInt(z, 4);
    TEST_ASSERT_EQUAL_HEX64(0x12345678, w);

    w = toInt(z, 5);
    TEST_ASSERT_EQUAL_HEX64(0x123456789A, w);

    w = toInt(z, 2);
    TEST_ASSERT_EQUAL_HEX64(0x1234, w);

    w = toInt(z, 1);
    TEST_ASSERT_EQUAL_HEX64(0x12, w);

}

void test_function_chain() {
    ADRS adrs = {0};
    char out[SLH_PARAM_n];

    const unsigned char expected[SLH_PARAM_n] = {
        0xb9, 0xcc, 0x9d, 0x1d, 0x6e, 0x42, 0x1e, 0x8f,
        0x38, 0x86, 0xf1, 0x73, 0xc9, 0x8f, 0xea, 0x77,
        0xa9, 0x03, 0xce, 0xf4, 0xe8, 0xf0, 0x3a, 0x28,
        0x92, 0x61, 0x6b, 0x26, 0xb0, 0x2d, 0xfb, 0x16
    };

    chain(m, 0, 5, pk_seed, &adrs, out);
    
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, out, SLH_PARAM_n);
}

void test_base_2b() {
    uint8_t x[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    uint16_t out[4];// = {0};
    uint16_t expected[4] = {1, 2, 3, 4};
    base_2b(x, 8, 4, 4, out);
    TEST_ASSERT_EQUAL_HEX16_ARRAY(expected, out, 4);


    uint8_t x1[5] = {0x98, 0x76, 0x54, 0x32, 0x10};
    uint16_t out1[10];// = {0};
    uint16_t expected1[10] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    base_2b(x1, 5, 4, 10, out1);
    TEST_ASSERT_EQUAL_HEX16_ARRAY(expected1, out1, 10);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_function_BE32);
    RUN_TEST(test_function_BE64);
    RUN_TEST(test_function_toInt);
    RUN_TEST(test_function_chain);
    RUN_TEST(test_base_2b);

    return UNITY_END();
}

