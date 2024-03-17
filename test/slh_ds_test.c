#include "unity.h"
#include "slh_common.h"


void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void test_struct_Address(void) {
    ADRS adrs = {0};
    char zeros[32] = {0};

    TEST_ASSERT_EQUAL(32, sizeof(adrs));


    TEST_ASSERT_EQUAL_MEMORY(zeros, &adrs, 32);

    // Layer address
    uint8_t testuint8 = 0x01;
    uint32_t testint32 = 0x12345678;
    setLayerAddress(&adrs, testuint8);
    TEST_ASSERT_EQUAL_MEMORY(&testuint8, &(adrs.layer), 1);


    // TODO the rest

    setKeyPairAddress(&adrs, 0x12345678);
    TEST_ASSERT_EQUAL_HEX32(0x12345678, getKeyPairAddress(&adrs));
}


int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_struct_Address);
    return UNITY_END();
}

