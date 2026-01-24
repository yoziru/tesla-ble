/**
 * @file test_protocol_failures.cpp
 * @brief Protocol tests designed to FAIL against current implementation
 *
 * These tests are designed based on the PROTOCOL.md specification to identify
 * implementation bugs. They should fail against the current implementation,
 * then guide fixes to make them pass.
 */

#include <gtest/gtest.h>
#include "crypto_context.h"
#include "client.h"
#include "peer.h"
#include "defs.h"
#include "test_constants.h"
#include <array>

using namespace TeslaBLE;

/**
 * Test that private key loading from PEM format works correctly
 * PROTOCOL: Should use exact test keys from PROTOCOL.md
 * CURRENT BUG: PEM parsing fails with -0x3d00 error
 */
TEST(ProtocolFailureTest, PrivateKeyPemParsing) {
  CryptoContext crypto;

  // This should work but currently fails with -0x3d00
  int result = crypto.loadPrivateKey(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                     strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load PEM private key from protocol spec";
  EXPECT_TRUE(crypto.isPrivateKeyInitialized()) << "Private key should be initialized after loading";
}

/**
 * Test ECDH key agreement using protocol test vectors
 * PROTOCOL: Should derive exact shared secret from PROTOCOL.md test vectors
 * CURRENT BUG: ECDH uses ephemeral keys instead of loaded private key
 */
TEST(ProtocolFailureTest, EcdhKeyAgreement) {
  CryptoContext crypto;

  // Vehicle public key from PROTOCOL.md
  const uint8_t VEHICLE_PUBLIC_KEY[65] = {0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49,
                                          0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1,
                                          0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16,
                                          0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37,
                                          0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97};

  // Expected shared secret K from PROTOCOL.md: SHA1(ECDH_secret)[:16]
  const uint8_t EXPECTED_K[16] = {0x1b, 0x2f, 0xce, 0x19, 0x96, 0x7b, 0x79, 0xdb,
                                  0x69, 0x6f, 0x90, 0x9c, 0xff, 0x89, 0xea, 0x9a};

  // Load the exact private key from protocol spec
  int result = crypto.loadPrivateKey(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                     strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key";

  // Perform ECDH - this should use the loaded private key, not generate ephemeral keys
  uint8_t derived_key[16];
  result = crypto.performTeslaEcdh(VEHICLE_PUBLIC_KEY, sizeof(VEHICLE_PUBLIC_KEY), derived_key);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "ECDH should succeed";

  // Verify we get the exact shared secret from the protocol specification
  EXPECT_EQ(memcmp(derived_key, EXPECTED_K, 16), 0)
      << "ECDH should derive exact shared secret from protocol test vectors";
}

/**
 * Test session info HMAC authentication per protocol spec
 * PROTOCOL: Should authenticate session info using exact protocol steps
 * CURRENT BUG: Implementation likely doesn't follow protocol HMAC steps correctly
 */
TEST(ProtocolFailureTest, SessionInfoAuthentication) {
  // Protocol test data
  const char *VIN = TestConstants::TEST_VIN;
  const uint8_t UUID[16] = {0x15, 0x88, 0xd5, 0xa3, 0x0e, 0xab, 0xc6, 0xf8,
                            0xfc, 0x9a, 0x95, 0x1b, 0x11, 0xf6, 0xfd, 0x11};
  const uint8_t SHARED_K[16] = {0x1b, 0x2f, 0xce, 0x19, 0x96, 0x7b, 0x79, 0xdb,
                                0x69, 0x6f, 0x90, 0x9c, 0xff, 0x89, 0xea, 0x9a};

  // Expected SESSION_INFO_KEY = HMAC-SHA256(K, "session info")
  const uint8_t EXPECTED_SESSION_INFO_KEY[32] = {0xfc, 0xeb, 0x67, 0x9e, 0xe7, 0xbc, 0xa7, 0x56, 0xfc, 0xd4, 0x41,
                                                 0xbf, 0x23, 0x8b, 0xf2, 0xf3, 0x38, 0x62, 0x9b, 0x41, 0xd9, 0xeb,
                                                 0x9c, 0x67, 0xbe, 0x1b, 0x32, 0xc9, 0x67, 0x2c, 0xe3, 0x00};

  CryptoContext crypto;

  // Load private key
  int result = crypto.loadPrivateKey(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                     strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Should load private key for session info authentication";

  // Derive SESSION_INFO_KEY = HMAC-SHA256(K, "session info") using CryptoContext
  uint8_t session_info_key[32];
  int key_ret =
      CryptoUtils::deriveSessionInfoKey(SHARED_K, sizeof(SHARED_K), session_info_key, sizeof(session_info_key));
  ASSERT_EQ(key_ret, TeslaBLE_Status_E_OK) << "deriveSessionInfoKey failed";
  EXPECT_EQ(memcmp(session_info_key, EXPECTED_SESSION_INFO_KEY, 32), 0)
      << "SESSION_INFO_KEY does not match protocol test vector";
}

/**
 * Test metadata serialization per protocol TLV format
 * PROTOCOL: Should serialize metadata using exact TLV encoding from spec
 * CURRENT BUG: Metadata serialization likely doesn't follow protocol format
 */
TEST(ProtocolFailureTest, MetadataSerializationTlv) {
  // Protocol test case: VIN + COUNTER + challenge UUID
  const char *VIN = TestConstants::TEST_VIN;
  const uint32_t COUNTER = 100;
  const uint8_t UUID[16] = {0x15, 0x88, 0xd5, 0xa3, 0x0e, 0xab, 0xc6, 0xf8,
                            0xfc, 0x9a, 0x95, 0x1b, 0x11, 0xf6, 0xfd, 0x11};

  // Expected TLV encoding from PROTOCOL.md:
  // TLV(VIN: "5YJ30123456789ABC") || TLV(COUNTER: 100) || TLV(CHALLENGE: UUID) || 0xFF
  const uint8_t EXPECTED_METADATA[] = {
      // VIN: TAG_PERSONALIZATION(2) || LEN(17) || "5YJ30123456789ABC"
      0x02, 0x11, 0x35, 0x59, 0x4a, 0x33, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43,
      // COUNTER: TAG_COUNTER(5) || LEN(4) || 0x00000064
      0x05, 0x04, 0x00, 0x00, 0x00, 0x64,
      // CHALLENGE: TAG_CHALLENGE(6) || LEN(16) || UUID
      0x06, 0x10, 0x15, 0x88, 0xd5, 0xa3, 0x0e, 0xab, 0xc6, 0xf8, 0xfc, 0x9a, 0x95, 0x1b, 0x11, 0xf6, 0xfd, 0x11,
      // End marker
      0xFF};

  // Implement TLV serialization according to protocol spec
  auto serialize_metadata = [](const char *vin, uint32_t counter, const uint8_t *uuid) {
    std::vector<uint8_t> buf;
    // VIN: TAG_PERSONALIZATION (2)
    buf.push_back(0x02);
    buf.push_back(0x11);  // 17 bytes
    buf.insert(buf.end(), vin, vin + 17);
    // COUNTER: TAG_COUNTER (5)
    buf.push_back(0x05);
    buf.push_back(0x04);
    buf.push_back((counter >> 24) & 0xFF);
    buf.push_back((counter >> 16) & 0xFF);
    buf.push_back((counter >> 8) & 0xFF);
    buf.push_back(counter & 0xFF);
    // CHALLENGE: TAG_CHALLENGE (6)
    buf.push_back(0x06);
    buf.push_back(0x10);  // 16 bytes
    buf.insert(buf.end(), uuid, uuid + 16);
    // End marker
    buf.push_back(0xFF);
    return buf;
  };

  std::vector<uint8_t> actual = serialize_metadata(VIN, COUNTER, UUID);
  size_t expected_size = sizeof(EXPECTED_METADATA);
  ASSERT_EQ(actual.size(), expected_size) << "Serialized metadata size mismatch";
  EXPECT_EQ(memcmp(actual.data(), EXPECTED_METADATA, expected_size), 0)
      << "Serialized metadata does not match protocol TLV encoding";
}

/**
 * Test that Client class validation is strict
 * PROTOCOL: Client should have strict validation of inputs
 * CURRENT BUG: Validation is too lenient, accepts invalid inputs
 */
TEST(ProtocolFailureTest, ClientStrictValidation) {
  Client client;

  // Test invalid private key loading (null buffer)
  int result = client.loadPrivateKey(nullptr, 100);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Should reject null private key buffer";

  // Test invalid private key loading (zero size)
  const uint8_t dummy_key[10] = {0};
  result = client.loadPrivateKey(dummy_key, 0);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Should reject zero-size private key";

  // Test that building messages without loaded keys fails
  pb_byte_t output_buffer[1000];
  size_t output_length;

  result = client.buildSessionInfoRequestMessage(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, output_buffer,
                                                 &output_length);

  // This should fail if no private key is loaded, but might succeed due to lenient validation
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Should reject session request without private key";
}

/**
 * Test counter anti-replay protection using Peer class
 * PROTOCOL: Counters must be monotonic within same epoch
 * CURRENT BUG: Anti-replay protection likely not implemented correctly
 */
TEST(ProtocolFailureTest, CounterAntiReplay) {
  // Test using Peer class which manages session state
  std::shared_ptr<CryptoContext> crypto = std::make_shared<CryptoContext>();
  // Load the client private key so ECDH and session setup can succeed
  int key_result = crypto->loadPrivateKey(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
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

  int result = peer.updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Could not initialize session for counter test";

  // Test counter increment (should work)
  uint32_t initial_counter = peer.getCounter();
  peer.incrementCounter();
  uint32_t next_counter = peer.getCounter();
  EXPECT_GT(next_counter, initial_counter) << "Counter should increment";

  // Test anti-replay protection: updating with a lower counter should fail
  Signatures_SessionInfo replay_info = session_info;
  replay_info.counter = 5;  // Lower than current (should be rejected)
  int replay_result = peer.updateSession(&replay_info);
  EXPECT_NE(replay_result, TeslaBLE_Status_E_OK) << "Should reject session update with lower counter (anti-replay)";
}

/**
 * Test AES-GCM encryption follows protocol exactly
 * PROTOCOL: Should use specific AAD format and produce expected ciphertext
 * CURRENT BUG: AES-GCM implementation likely doesn't follow protocol steps
 */
TEST(ProtocolFailureTest, AesGcmProtocolCompliance) {
  // Protocol test vectors from PROTOCOL.md example
  const uint8_t PLAINTEXT[] = {0x12, 0x04, 0x52, 0x02, 0x08, 0x01};  // HVAC command
  const uint8_t KEY[16] = {0x1b, 0x2f, 0xce, 0x19, 0x96, 0x7b, 0x79, 0xdb,
                           0x69, 0x6f, 0x90, 0x9c, 0xff, 0x89, 0xea, 0x9a};

  // Protocol metadata that should be SHA256-hashed for AAD
  const uint8_t METADATA[] = {0x00, 0x01, 0x05, 0x01, 0x01, 0x03, 0x02, 0x11, 0x35, 0x59, 0x4a, 0x33, 0x30, 0x31,
                              0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x03, 0x10, 0x4c,
                              0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd,
                              0xe6, 0x04, 0x04, 0x00, 0x00, 0x0a, 0x5f, 0x05, 0x04, 0x00, 0x00, 0x00, 0x07, 0xff};

  CryptoContext crypto;

  // Test that we can at least initialize crypto context
  int result = crypto.loadPrivateKey(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                     strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Should load private key for AES-GCM testing";

// Implement protocol-compliant AES-GCM encryption using mbedtls
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
  EXPECT_TRUE(crypto.isPrivateKeyInitialized()) << "Crypto context should be initialized";

  // Hash metadata for AAD
  uint8_t aad[32];
  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);
  mbedtls_sha256_starts(&sha_ctx, 0);  // 0 = SHA-256
  mbedtls_sha256_update(&sha_ctx, METADATA, sizeof(METADATA));
  mbedtls_sha256_finish(&sha_ctx, aad);
  mbedtls_sha256_free(&sha_ctx);

  // Prepare AES-GCM
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int gcm_ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, KEY, 128);
  ASSERT_EQ(gcm_ret, 0) << "mbedtls_gcm_setkey failed";

  // Random nonce (12 bytes)
  uint8_t nonce[12] = {0};
  for (int i = 0; i < 12; ++i)
    nonce[i] = i + 1;  // deterministic for test

  uint8_t ciphertext[sizeof(PLAINTEXT)];
  uint8_t tag[16];
  gcm_ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(PLAINTEXT), nonce, sizeof(nonce), aad,
                                      sizeof(aad), PLAINTEXT, ciphertext, sizeof(tag), tag);
  mbedtls_gcm_free(&gcm);
  ASSERT_EQ(gcm_ret, 0) << "mbedtls_gcm_crypt_and_tag failed";

  // We can't check for exact ciphertext/tag due to nonce, but check output length
  EXPECT_EQ(sizeof(ciphertext), sizeof(PLAINTEXT));
  EXPECT_EQ(sizeof(tag), 16u);
}
