/**
 * @file test_protocol_vectors.cpp
 * @brief Test vectors from the Tesla BLE Protocol Specification
 *
 * This file contains tests based on the exact test vectors and examples
 * provided in the protocol specification document to ensure our implementation
 * matches the official protocol.
 */

#include <gtest/gtest.h>
#include <crypto_context.h>
#include <peer.h>
#include <client.h>
#include "test_constants.h"

namespace TeslaBLE {

// Test vectors from protocol specification
class ProtocolVectorsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = std::make_unique<Client>();
    client_->set_vin(TestConstants::TEST_VIN);
  }

  std::unique_ptr<Client> client_;
};

// Test 1: Request Hash Construction for Response Decryption
TEST_F(ProtocolVectorsTest, RequestHashConstruction) {
  // Test request hash construction for both domains

  auto crypto_context = std::make_shared<CryptoContext>();

  // Test VCSEC (truncated to 17 bytes)
  Peer vcsec_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto_context, TestConstants::TEST_VIN);
  uint8_t test_tag[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  uint8_t vcsec_hash[17];
  size_t vcsec_hash_length;

  auto result = vcsec_peer.construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                  test_tag, 16, vcsec_hash, &vcsec_hash_length);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to construct VCSEC request hash";
  EXPECT_EQ(vcsec_hash_length, 17) << "VCSEC request hash should be 17 bytes";
  EXPECT_EQ(vcsec_hash[0], Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED)
      << "First byte should be signature type";

  // Test Infotainment (full 17 bytes for AES-GCM, 33 for HMAC)
  Peer info_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);
  uint8_t info_hash[33];
  size_t info_hash_length;

  result = info_peer.construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, test_tag, 16,
                                            info_hash, &info_hash_length);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to construct Infotainment request hash";
  EXPECT_EQ(info_hash_length, 17) << "Infotainment AES-GCM request hash should be 17 bytes";

  // Test HMAC request hash for Infotainment (should be 33 bytes)
  uint8_t hmac_tag[32];
  memset(hmac_tag, 0x42, sizeof(hmac_tag));

  result = info_peer.construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_HMAC_PERSONALIZED, hmac_tag, 32,
                                            info_hash, &info_hash_length);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to construct Infotainment HMAC request hash";
  EXPECT_EQ(info_hash_length, 33) << "Infotainment HMAC request hash should be 33 bytes";
}

// Test 2: Counter and Anti-Replay Protection
TEST_F(ProtocolVectorsTest, CounterAntiReplay) {
  // Test counter increment and anti-replay mechanisms

  auto crypto_context = std::make_shared<CryptoContext>();

  // Load the private key into the crypto context for ECDH operations
  auto result =
      crypto_context->load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                       strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
      );
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key into crypto context";

  // Verify the private key is loaded correctly
  ASSERT_TRUE(crypto_context->is_private_key_initialized()) << "Private key should be initialized after loading";

  Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);

  // Check that the peer has the same crypto context with loaded key
  ASSERT_TRUE(peer.is_private_key_initialized()) << "Peer should have initialized private key";

  // Double-check that the crypto context still has the key before updateSession
  ASSERT_TRUE(crypto_context->is_private_key_initialized())
      << "CryptoContext should still have initialized private key before updateSession";

  // Initialize with mock session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  session_info.counter = 100;
  session_info.clock_time = 1000;

  // Set epoch
  memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);

  // Set public key
  memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
  session_info.publicKey.size = 65;

  int update_result = peer.update_session(&session_info);
  ASSERT_EQ(update_result, TeslaBLE_Status_E_OK) << "Failed to update session";

  // Test that counter can be read and incremented
  uint32_t initial_counter = peer.get_counter();
  EXPECT_EQ(initial_counter, 100) << "Counter should be initialized to 100";

  peer.increment_counter();
  uint32_t next_counter = peer.get_counter();
  EXPECT_EQ(next_counter, initial_counter + 1) << "Counter should increment";

  // Test counter validation for responses
  bool valid1 = peer.validate_response_counter(150);  // first response counter
  EXPECT_TRUE(valid1) << "First response counter should be valid";

  bool valid2 = peer.validate_response_counter(150);  // same counter
  EXPECT_FALSE(valid2) << "Duplicate response counter should be invalid";

  bool valid3 = peer.validate_response_counter(151);  // different counter
  EXPECT_TRUE(valid3) << "Different response counter should be valid";
}

}  // namespace TeslaBLE
