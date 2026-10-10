/**
 * @file test_protocol_compliance.cpp
 * @brief Protocol compliance tests based on PROTOCOL.md
 */

#include <gtest/gtest.h>
#include "crypto_context.h"
#include "client.h"
#include "errors.h"
#include "peer.h"
#include "test_constants.h"
#include <cstring>

using namespace TeslaBLE;

/**
 * Test that private key loading from PEM format works correctly
 * PROTOCOL: Should use exact test keys from PROTOCOL.md
 */
TEST(ProtocolFailureTest, PrivateKeyPemParsing) {
  CryptoContext crypto;

  auto result = crypto.load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load PEM private key from protocol spec";
  EXPECT_TRUE(crypto.is_private_key_initialized()) << "Private key should be initialized after loading";
}

/**
 * Test ECDH key agreement using protocol test vectors
 * PROTOCOL: Should derive exact shared secret from PROTOCOL.md test vectors
 */
TEST(ProtocolFailureTest, EcdhKeyAgreement) {
  CryptoContext crypto;

  // Vehicle public key from PROTOCOL.md
  const uint8_t vehicle_public_key[65] = {0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49,
                                          0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1,
                                          0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16,
                                          0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37,
                                          0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97};

  // Expected shared secret K from PROTOCOL.md: SHA1(ECDH_secret)[:16]
  const uint8_t expected_k[16] = {0x1b, 0x2f, 0xce, 0x19, 0x96, 0x7b, 0x79, 0xdb,
                                  0x69, 0x6f, 0x90, 0x9c, 0xff, 0x89, 0xea, 0x9a};

  // Load the exact private key from protocol spec
  auto result = crypto.load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key";

  // Perform ECDH - this should use the loaded private key, not generate ephemeral keys
  uint8_t derived_key[16];
  result = crypto.perform_tesla_ecdh(vehicle_public_key, sizeof(vehicle_public_key), derived_key);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "ECDH should succeed";

  // Verify we get the exact shared secret from the protocol specification
  EXPECT_EQ(memcmp(derived_key, expected_k, 16), 0)
      << "ECDH should derive exact shared secret from protocol test vectors";
}

/**
 * Test session info HMAC authentication per protocol spec
 * PROTOCOL: Should authenticate session info using exact protocol steps
 */
TEST(ProtocolFailureTest, SessionInfoAuthentication) {
  // Protocol test data
  const char *vin = TestConstants::TEST_VIN;
  const uint8_t uuid[16] = {0x15, 0x88, 0xd5, 0xa3, 0x0e, 0xab, 0xc6, 0xf8,
                            0xfc, 0x9a, 0x95, 0x1b, 0x11, 0xf6, 0xfd, 0x11};
  const uint8_t shared_k[16] = {0x1b, 0x2f, 0xce, 0x19, 0x96, 0x7b, 0x79, 0xdb,
                                0x69, 0x6f, 0x90, 0x9c, 0xff, 0x89, 0xea, 0x9a};

  // Expected session_info_key = HMAC-SHA256(K, "session info")
  const uint8_t expected_session_info_key[32] = {0xfc, 0xeb, 0x67, 0x9e, 0xe7, 0xbc, 0xa7, 0x56, 0xfc, 0xd4, 0x41,
                                                 0xbf, 0x23, 0x8b, 0xf2, 0xf3, 0x38, 0x62, 0x9b, 0x41, 0xd9, 0xeb,
                                                 0x9c, 0x67, 0xbe, 0x1b, 0x32, 0xc9, 0x67, 0x2c, 0xe3, 0x00};

  CryptoContext crypto;

  // Load private key
  auto result = crypto.load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Should load private key for session info authentication";

  // Derive session_info_key = HMAC-SHA256(K, "session info") using CryptoContext
  uint8_t session_info_key[32];
  int key_ret =
      CryptoUtils::derive_session_info_key(shared_k, sizeof(shared_k), session_info_key, sizeof(session_info_key));
  ASSERT_EQ(key_ret, TeslaBLE_Status_E_OK) << "derive_session_info_key failed";
  EXPECT_EQ(memcmp(session_info_key, expected_session_info_key, 32), 0)
      << "session_info_key does not match protocol test vector";
}

/**
 * Test that Client class validation is strict
 * PROTOCOL: Client should have strict validation of inputs
 */
TEST(ProtocolFailureTest, ClientStrictValidation) {
  Client client;

  // Test invalid private key loading (null buffer)
  auto result = client.load_private_key(nullptr, 100);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Should reject null private key buffer";

  // Test invalid private key loading (zero size)
  const uint8_t dummy_key[10] = {0};
  result = client.load_private_key(dummy_key, 0);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Should reject zero-size private key";

  // Test that building messages without loaded keys fails
  pb_byte_t output_buffer[1000];
  size_t output_length;

  result = client.build_session_info_request_message(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, output_buffer,
                                                     &output_length);

  // This should fail if no private key is loaded, but might succeed due to lenient validation
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Should reject session request without private key";
}

/**
 * Test counter anti-replay protection using Peer class
 * PROTOCOL: Counters must be monotonic within same epoch
 */
TEST(ProtocolFailureTest, CounterAntiReplay) {
  // Test using Peer class which manages session state
  std::shared_ptr<CryptoContext> crypto = std::make_shared<CryptoContext>();
  // Load the client private key so ECDH and session setup can succeed
  TeslaBLE_Status_E key_result =
      crypto->load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                               strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  ASSERT_EQ(key_result, TeslaBLE_Status_E_OK) << "Failed to load client private key for session test";

  Peer peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto, TestConstants::TEST_VIN);

  // Create valid session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_zero;
  session_info.counter = 10;
  session_info.clock_time = 1000;

  // Set valid epoch
  uint8_t epoch[16] = {0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 0xe6};
  memcpy(session_info.epoch, epoch, 16);

  // Use the real vehicle public key from protocol test vectors
  memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
  session_info.publicKey.size = 65;

  auto result = peer.update_session(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Could not initialize session for counter test";

  // Test counter increment (should work)
  uint32_t initial_counter = peer.get_counter();
  peer.increment_counter();
  uint32_t next_counter = peer.get_counter();
  EXPECT_GT(next_counter, initial_counter) << "Counter should increment";

  // Test anti-replay protection: updating with a lower counter should fail
  Signatures_SessionInfo replay_info = session_info;
  replay_info.counter = 5;  // Lower than current (should be rejected)
  int replay_result = peer.update_session(&replay_info);
  EXPECT_NE(replay_result, TeslaBLE_Status_E_OK) << "Should reject session update with lower counter (anti-replay)";
}
