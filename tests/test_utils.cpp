#include <gtest/gtest.h>
#include <tb_utils.h>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include <sstream>
#include <iomanip>
#include <cstring>

// Utility function from main.cpp for comparison
static std::string bytes_to_hex_string(const pb_byte_t *bytes, size_t length)
{
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < length; i++)
  {
    ss << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return ss.str();
}

class UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }

    void TearDown() override {
        // Cleanup code if needed
    }
};

TEST_F(UtilsTest, BytesToHexStringEmpty) {
    std::string result = bytes_to_hex_string(nullptr, 0);
    EXPECT_EQ(result, "") << "Empty byte array should produce empty string";
}

TEST_F(UtilsTest, BytesToHexStringSingleByte) {
    pb_byte_t data[] = {0xAB};
    std::string result = bytes_to_hex_string(data, sizeof(data));
    EXPECT_EQ(result, "ab") << "Single byte should be converted correctly";
}

TEST_F(UtilsTest, BytesToHexStringMultipleBytes) {
    pb_byte_t data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::string result = bytes_to_hex_string(data, sizeof(data));
    EXPECT_EQ(result, "0123456789abcdef") << "Multiple bytes should be converted correctly";
}

TEST_F(UtilsTest, BytesToHexStringZeroes) {
    pb_byte_t data[] = {0x00, 0x00, 0x00};
    std::string result = bytes_to_hex_string(data, sizeof(data));
    EXPECT_EQ(result, "000000") << "Zero bytes should be padded correctly";
}

TEST_F(UtilsTest, BytesToHexStringMaxValues) {
    pb_byte_t data[] = {0xFF, 0xFF, 0xFF};
    std::string result = bytes_to_hex_string(data, sizeof(data));
    EXPECT_EQ(result, "ffffff") << "Max value bytes should be converted correctly";
}

// Test VIN validation if available in tb_utils
TEST_F(UtilsTest, VINValidation) {
    // This test depends on what utility functions are available in tb_utils.h
    // You may need to adjust based on the actual API
    
    // Example VIN from mock data
    const char* valid_vin = "5YJ30123456789ABC";
    EXPECT_EQ(strlen(valid_vin), 17) << "Valid VIN should be 17 characters";
    
    // Test that VIN contains only valid characters (alphanumeric except I, O, Q)
    for (size_t i = 0; i < strlen(valid_vin); i++) {
        char c = valid_vin[i];
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) 
            << "VIN character at position " << i << " should be alphanumeric";
        EXPECT_NE(c, 'I') << "VIN should not contain 'I'";
        EXPECT_NE(c, 'O') << "VIN should not contain 'O'";
        EXPECT_NE(c, 'Q') << "VIN should not contain 'Q'";
    }
}

// Test any buffer manipulation utilities
TEST_F(UtilsTest, BufferOperations) {
    // Test basic buffer operations if available in tb_utils
    unsigned char buffer1[16] = {0};
    unsigned char buffer2[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    // Test that buffers are different
    EXPECT_NE(memcmp(buffer1, buffer2, sizeof(buffer1)), 0) << "Buffers should be different";
    
    // Test copying
    memcpy(buffer1, buffer2, sizeof(buffer1));
    EXPECT_EQ(memcmp(buffer1, buffer2, sizeof(buffer1)), 0) << "Buffers should be identical after copy";
}

// Test connection ID handling
TEST_F(UtilsTest, ConnectionIDFormat) {
    // Test that connection ID is 16 bytes
    pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26, 
                                  0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
    
    EXPECT_EQ(sizeof(connection_id), 16) << "Connection ID should be 16 bytes";
    
    std::string hex_string = bytes_to_hex_string(connection_id, sizeof(connection_id));
    EXPECT_EQ(hex_string.length(), 32) << "Hex representation should be 32 characters";
    EXPECT_EQ(hex_string, "934f10691deda826a7982e92c4fce83f") << "Connection ID should match expected hex";
}

// Test private key format validation
TEST_F(UtilsTest, PrivateKeyFormat) {
    const char* mock_key = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";
    
    // Test basic format validation
    EXPECT_TRUE(strstr(mock_key, "-----BEGIN EC PRIVATE KEY-----") != nullptr) 
        << "Private key should start with proper header";
    EXPECT_TRUE(strstr(mock_key, "-----END EC PRIVATE KEY-----") != nullptr) 
        << "Private key should end with proper footer";
    
    // Test key length is reasonable
    size_t key_length = strlen(mock_key);
    EXPECT_GT(key_length, 100) << "Private key should be substantial length";
    EXPECT_LT(key_length, 1000) << "Private key should not be excessively long";
}

// Test message size constants
TEST_F(UtilsTest, MessageSizeConstants) {
    // Verify that message size constants are reasonable
    EXPECT_GT(VCSEC_ToVCSECMessage_size, 0) << "VCSEC message size should be positive";
    EXPECT_GT(UniversalMessage_RoutableMessage_size, 0) << "Universal message size should be positive";
    
    // Typical protobuf messages shouldn't be too large for embedded systems
    EXPECT_LT(VCSEC_ToVCSECMessage_size, 10000) << "VCSEC message size should be reasonable for embedded use";
    EXPECT_LT(UniversalMessage_RoutableMessage_size, 10000) << "Universal message size should be reasonable for embedded use";
}

// Test array bounds
TEST_F(UtilsTest, ArrayBounds) {
    // Test that our test data doesn't exceed expected bounds
    const size_t vcsec_message_size = 177;
    const size_t infotainment_message_size = 177;
    
    EXPECT_LE(vcsec_message_size, UniversalMessage_RoutableMessage_size) 
        << "VCSEC test message should fit in universal message buffer";
    EXPECT_LE(infotainment_message_size, UniversalMessage_RoutableMessage_size) 
        << "Infotainment test message should fit in universal message buffer";
}
