#include "unity.h"
#include "slh_common.h"

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

void test_chain() {

}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_function_BE32);
    RUN_TEST(test_function_BE64);
    RUN_TEST(test_function_toInt);
    // RUN_TEST(test_chain);
    
    return UNITY_END();
}

