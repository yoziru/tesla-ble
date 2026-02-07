#include <gtest/gtest.h>
#include <client.h>
#include <cstring>
#include "test_constants.h"

using namespace TeslaBLE;

class KeyGenerationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = std::make_unique<Client>();
    client_->set_vin(TestConstants::TEST_VIN);
  }

  void TearDown() override { client_.reset(); }

  std::unique_ptr<Client> client_;
};

TEST_F(KeyGenerationTest, CreatePrivateKeyGeneratesValidKey) {
  auto status = client_->create_private_key();
  EXPECT_EQ(status, TeslaBLE_Status_E_OK) << "Private key creation should succeed";

  // Verify we can get the generated key
  unsigned char private_key_buffer[512];  // Larger buffer for generated keys
  size_t private_key_length;
  auto get_status = client_->get_private_key(private_key_buffer, sizeof(private_key_buffer), &private_key_length);

  EXPECT_EQ(get_status, TeslaBLE_Status_E_OK) << "Should be able to retrieve generated private key";
  EXPECT_GT(private_key_length, 0) << "Generated private key should have non-zero length";
}

TEST_F(KeyGenerationTest, LoadValidPrivateKey) {
  auto status =
      client_->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  EXPECT_EQ(status, TeslaBLE_Status_E_OK) << "Failed to load valid private key";
}

TEST_F(KeyGenerationTest, LoadInvalidPrivateKeyFails) {
  // Test with completely malformed PEM data
  const char *malformed_pem = "-----BEGIN EC PRIVATE KEY-----\nTHIS_IS_NOT_VALID_BASE64\n-----END EC PRIVATE KEY-----";
  auto status =
      client_->load_private_key(reinterpret_cast<const unsigned char *>(malformed_pem), strlen(malformed_pem) + 1);
  EXPECT_NE(status, TeslaBLE_Status_E_OK) << "Loading malformed private key should fail";

  // Test with RSA key - should fail at Tesla protocol validation (not EC key)
  const char *rsa_key = R"(-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBvM5OyMI5r8tP
gAmNBb65cZR0n9FVOVYgvdCk8H5+RAMCIQCJy7tydZmY4t6yy7u5k5kn4D1Y1U4u
kTCT4R0m6t3XbwIhAOWl2yQ7aA4Q1j8rWtNgQF3Y5Vx+QQChF2xGJnE+5c2u
-----END RSA PRIVATE KEY-----)";
  status = client_->load_private_key(reinterpret_cast<const unsigned char *>(rsa_key), strlen(rsa_key) + 1);
  EXPECT_NE(status, TeslaBLE_Status_E_OK) << "Loading RSA key should fail - Tesla protocol requires EC keys";

  // Test with missing header
  const char *no_header = "MHcCAQEEIDRO5bRmp88e6xK29QMx2y5exYNO9fS+";
  status = client_->load_private_key(reinterpret_cast<const unsigned char *>(no_header), strlen(no_header) + 1);
  EXPECT_NE(status, TeslaBLE_Status_E_OK) << "Loading key without PEM header should fail";
}

TEST_F(KeyGenerationTest, LoadEmptyPrivateKeyFails) {
  auto status = client_->load_private_key(nullptr, 0);
  EXPECT_NE(status, TeslaBLE_Status_E_OK) << "Loading null/empty private key should fail";
}

TEST_F(KeyGenerationTest, GetPrivateKeyWithoutLoadingFails) {
  unsigned char private_key_buffer[512];
  size_t private_key_length;
  auto status = client_->get_private_key(private_key_buffer, sizeof(private_key_buffer), &private_key_length);
  EXPECT_NE(status, TeslaBLE_Status_E_OK) << "Getting private key without loading/creating should fail";
}

TEST_F(KeyGenerationTest, GetPrivateKeyWithInsufficientBufferFails) {
  // Load a valid key first
  auto load_status =
      client_->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  ASSERT_EQ(load_status, TeslaBLE_Status_E_OK) << "Failed to load private key";

  // Try to get key with too small buffer
  unsigned char small_buffer[10];
  size_t private_key_length;
  auto get_status = client_->get_private_key(small_buffer, sizeof(small_buffer), &private_key_length);
  EXPECT_NE(get_status, TeslaBLE_Status_E_OK) << "Getting private key with insufficient buffer should fail";
}

TEST_F(KeyGenerationTest, RepeatedKeyGenerationWorks) {
  // First generation
  auto status1 = client_->create_private_key();
  EXPECT_EQ(status1, TeslaBLE_Status_E_OK) << "First private key creation should succeed";

  // Second generation (should replace first)
  auto status2 = client_->create_private_key();
  EXPECT_EQ(status2, TeslaBLE_Status_E_OK) << "Second private key creation should succeed";

  // Verify we can still get a valid key
  unsigned char private_key_buffer[512];
  size_t private_key_length;
  auto get_status = client_->get_private_key(private_key_buffer, sizeof(private_key_buffer), &private_key_length);

  EXPECT_EQ(get_status, TeslaBLE_Status_E_OK) << "Should be able to retrieve second generated private key";
  EXPECT_GT(private_key_length, 0) << "Second generated private key should have non-zero length";
}
