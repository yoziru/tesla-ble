#include <gtest/gtest.h>
#include <client.h>
#include <cstring>
#include <sstream>
#include <iomanip>

// Mock data from PROTOCOL.md examples (same as in main.cpp)
static const char *MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

// Utility function from main.cpp
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

class ClientTest : public ::testing::Test {
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

TEST_F(ClientTest, CreateClient) {
    EXPECT_NE(client, nullptr);
}

TEST_F(ClientTest, SetVIN) {
    EXPECT_NO_THROW(client->setVIN(MOCK_VIN));
    // Note: No getter for VIN in the current API, so we can't verify it's set
}

TEST_F(ClientTest, LoadPrivateKey) {
    int status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
    EXPECT_EQ(status, 0) << "Failed to load private key";
}

TEST_F(ClientTest, CreatePrivateKey) {
    int status = client->createPrivateKey();
    EXPECT_EQ(status, 0) << "Failed to create private key";
}

TEST_F(ClientTest, GetPrivateKeyAfterLoading) {
    // First load a private key
    int load_status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
    ASSERT_EQ(load_status, 0) << "Failed to load private key";

    // Now get the private key
    unsigned char private_key_buffer[sizeof(MOCK_PRIVATE_KEY) + 1];
    size_t private_key_length;
    int get_status = client->getPrivateKey(private_key_buffer, sizeof(private_key_buffer), &private_key_length);
    
    EXPECT_EQ(get_status, 0) << "Failed to get private key";
    EXPECT_GT(private_key_length, 0) << "Private key length should be greater than 0";
    EXPECT_LE(private_key_length, sizeof(private_key_buffer)) << "Private key length should not exceed buffer size";
}

TEST_F(ClientTest, GetPeerWithValidDomain) {
    // Load private key first
    int status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
    ASSERT_EQ(status, 0) << "Failed to load private key";

    auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    EXPECT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

    auto infotainment_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    EXPECT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";
}

TEST_F(ClientTest, SetConnectionID) {
    pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26, 
                                  0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
    EXPECT_NO_THROW(client->setConnectionID(connection_id));
}

TEST_F(ClientTest, BuildWhiteListMessage) {
    // Load private key first
    int status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
    ASSERT_EQ(status, 0) << "Failed to load private key";

    unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
    size_t whitelist_message_length;
    
    int result = client->buildWhiteListMessage(
        Keys_Role_ROLE_CHARGING_MANAGER, 
        VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY, 
        whitelist_message_buffer, 
        &whitelist_message_length
    );
    
    EXPECT_EQ(result, 0) << "Failed to build whitelist message";
    EXPECT_GT(whitelist_message_length, 0) << "Whitelist message length should be greater than 0";
    EXPECT_LE(whitelist_message_length, sizeof(whitelist_message_buffer)) << "Message length should not exceed buffer size";
}
