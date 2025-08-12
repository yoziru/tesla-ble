#include <gtest/gtest.h>
#include <client.h>
#include <cstring>

// Mock data
static const char *MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

class KeyGenerationTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<TeslaBLE::Client>();
        client->setVIN(MOCK_VIN);
    }

    void TearDown() override {
        client.reset();
    }

    std::unique_ptr<TeslaBLE::Client> client;
};

TEST_F(KeyGenerationTest, CreatePrivateKeyGeneratesValidKey) {
    int status = client->createPrivateKey();
    EXPECT_EQ(status, 0) << "Private key creation should succeed";

    // Verify we can get the generated key
    unsigned char private_key_buffer[512]; // Larger buffer for generated keys
    size_t private_key_length;
    int get_status = client->getPrivateKey(private_key_buffer, sizeof(private_key_buffer), &private_key_length);
    
    EXPECT_EQ(get_status, 0) << "Should be able to retrieve generated private key";
    EXPECT_GT(private_key_length, 0) << "Generated private key should have non-zero length";
}

TEST_F(KeyGenerationTest, LoadValidPrivateKey) {
    int status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
    EXPECT_EQ(status, 0) << "Loading valid private key should succeed";
}

TEST_F(KeyGenerationTest, LoadInvalidPrivateKeyFails) {
    const char* invalid_key = "invalid_key_data";
    int status = client->loadPrivateKey(reinterpret_cast<const unsigned char*>(invalid_key), strlen(invalid_key));
    EXPECT_NE(status, 0) << "Loading invalid private key should fail";
}

TEST_F(KeyGenerationTest, LoadEmptyPrivateKeyFails) {
    int status = client->loadPrivateKey(nullptr, 0);
    EXPECT_NE(status, 0) << "Loading null/empty private key should fail";
}

TEST_F(KeyGenerationTest, GetPrivateKeyWithoutLoadingFails) {
    unsigned char private_key_buffer[512];
    size_t private_key_length;
    int status = client->getPrivateKey(private_key_buffer, sizeof(private_key_buffer), &private_key_length);
    EXPECT_NE(status, 0) << "Getting private key without loading/creating should fail";
}

TEST_F(KeyGenerationTest, GetPrivateKeyWithInsufficientBufferFails) {
    // Load a valid key first
    int load_status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
    ASSERT_EQ(load_status, 0) << "Failed to load private key";

    // Try to get key with too small buffer
    unsigned char small_buffer[10];
    size_t private_key_length;
    int get_status = client->getPrivateKey(small_buffer, sizeof(small_buffer), &private_key_length);
    EXPECT_NE(get_status, 0) << "Getting private key with insufficient buffer should fail";
}

TEST_F(KeyGenerationTest, RepeatedKeyGenerationWorks) {
    // First generation
    int status1 = client->createPrivateKey();
    EXPECT_EQ(status1, 0) << "First private key creation should succeed";

    // Second generation (should replace first)
    int status2 = client->createPrivateKey();
    EXPECT_EQ(status2, 0) << "Second private key creation should succeed";

    // Verify we can still get a valid key
    unsigned char private_key_buffer[512];
    size_t private_key_length;
    int get_status = client->getPrivateKey(private_key_buffer, sizeof(private_key_buffer), &private_key_length);
    
    EXPECT_EQ(get_status, 0) << "Should be able to retrieve second generated private key";
    EXPECT_GT(private_key_length, 0) << "Second generated private key should have non-zero length";
}
