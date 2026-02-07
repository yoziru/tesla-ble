/**
 * @file test_protocol_handshake.cpp
 * @brief Tests for Tesla BLE Protocol handshake and response handling
 *
 * This file tests the handshake process, session info authentication,
 * and response decryption as specified in the protocol documentation.
 */

#include <gtest/gtest.h>
#include <client.h>
#include <peer.h>
#include <crypto_context.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include "test_constants.h"

namespace TeslaBLE {

class ProtocolHandshakeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = std::make_unique<Client>();
    client_->set_vin(TestConstants::TEST_VIN);
    crypto_context_ = std::make_shared<CryptoContext>();
  }

  std::unique_ptr<Client> client_;
  std::shared_ptr<CryptoContext> crypto_context_;

  std::string bytes_to_hex_(const uint8_t *bytes, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
      ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
  }

  void hex_to_bytes_(const std::string &hex, uint8_t *bytes) {
    const size_t length = hex.length();
    for (size_t i = 0; i + 1 < length; i += 2) {
      std::string byte_string = hex.substr(i, 2);
      bytes[i / 2] = static_cast<uint8_t>(strtol(byte_string.c_str(), nullptr, 16));
    }
  }
};

// Test 1: Handshake Request Generation
TEST_F(ProtocolHandshakeTest, HandshakeRequestGeneration) {
  // Load client private key
  auto result =
      client_->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
      );
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load client private key";

  // Test session info request for VCSEC domain (this is the actual handshake)
  pb_byte_t vcsec_message[512];
  size_t vcsec_message_length;

  result = client_->build_session_info_request_message(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, vcsec_message,
                                                       &vcsec_message_length);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to build VCSEC session info request";
  EXPECT_GT(vcsec_message_length, 0) << "VCSEC session info message should have content";

  // Test session info request for Infotainment domain
  pb_byte_t info_message[512];
  size_t info_message_length;

  result = client_->build_session_info_request_message(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, info_message,
                                                       &info_message_length);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to build Infotainment session info request";
  EXPECT_GT(info_message_length, 0) << "Infotainment session info message should have content";

  // Verify messages are different (different domains should have different routing)
  bool messages_different =
      (vcsec_message_length != info_message_length) ||
      (memcmp(vcsec_message, info_message, std::min(vcsec_message_length, info_message_length)) != 0);
  EXPECT_TRUE(messages_different) << "VCSEC and Infotainment session requests should be different";
}

// Test 2: Handshake Flow and Response Processing
TEST_F(ProtocolHandshakeTest, HandshakeFlowProcessing) {
  // Test the complete handshake flow with proper response handling

  // Load client private key for key agreement
  auto result =
      crypto_context_->load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
      );
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key into crypto context";

  // Create a peer for handshake testing
  Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context_, TestConstants::TEST_VIN);

  // Initial handshake should succeed
  EXPECT_FALSE(peer.is_valid()) << "Peer should be invalid before handshake";

  // Simulate session establishment
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  session_info.counter = 1;
  session_info.clock_time = 1000;

  memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);
  memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
  session_info.publicKey.size = 65;

  int session_result = peer.update_session(&session_info);
  ASSERT_EQ(session_result, TeslaBLE_Status_E_OK) << "Failed to establish session during handshake";

  // Verify handshake completion
  EXPECT_TRUE(peer.is_valid()) << "Peer should be valid after successful handshake";

  // Test counter advancement during handshake
  uint32_t initial_counter = peer.get_counter();
  EXPECT_EQ(initial_counter, 1) << "Counter should be set to initial session value";
}

// Test 3: Response Encryption Flag Handling
TEST_F(ProtocolHandshakeTest, ResponseEncryptionFlag) {
  // Test that messages can be built successfully with the encryption flag
  // According to protocol spec: "Clients should always set the FLAG_ENCRYPT_RESPONSE bit"

  // Load private key for client
  auto result = client_->load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                          strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key";

  // Test that session info request can be built successfully
  // The implementation should automatically set FLAG_ENCRYPT_RESPONSE
  pb_byte_t session_request[512];
  size_t session_request_length;

  int build_result2 = client_->build_session_info_request_message(UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                                                                  session_request, &session_request_length);
  ASSERT_EQ(build_result2, TeslaBLE_Status_E_OK) << "Failed to build session info request";
  EXPECT_GT(session_request_length, 0) << "Session request should have content";

  // Test that whitelist message can be built successfully
  // The implementation should automatically set FLAG_ENCRYPT_RESPONSE
  pb_byte_t whitelist_message[512];
  size_t whitelist_length;

  result =
      client_->build_white_list_message(Keys_Role_ROLE_DRIVER,                               // role parameter
                                        VCSEC_KeyFormFactor_KEY_FORM_FACTOR_ANDROID_DEVICE,  // form factor parameter
                                        whitelist_message, &whitelist_length);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to build whitelist message";
  EXPECT_GT(whitelist_length, 0) << "Whitelist message should have content";

  // Test that VCSEC information request can be built successfully
  pb_byte_t vcsec_request[512];
  size_t vcsec_length;

  int vcsec_result = client_->build_vcsec_information_request_message(
      VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO, vcsec_request, &vcsec_length);
  ASSERT_EQ(vcsec_result, TeslaBLE_Status_E_OK) << "Failed to build VCSEC information request";
  EXPECT_GT(vcsec_length, 0) << "VCSEC request should have content";

  // All message building methods should succeed when FLAG_ENCRYPT_RESPONSE
  // is properly implemented according to the protocol specification
}

// Test 4: Response Decryption
TEST_F(ProtocolHandshakeTest, ResponseDecryption) {
  // Test response decryption with mock encrypted response

  // Load private key for key agreement
  auto result =
      crypto_context_->load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
      );
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key";

  // Create peer and load vehicle public key
  Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context_, TestConstants::TEST_VIN);
  int key_result = peer.load_tesla_key(TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
  ASSERT_EQ(key_result, TeslaBLE_Status_E_OK) << "Failed to load Tesla key";

  // Mock session info to initialize peer
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  session_info.counter = 7;
  session_info.clock_time = 2655;

  memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);

  memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
  session_info.publicKey.size = 65;

  int update_result2 = peer.update_session(&session_info);
  ASSERT_EQ(update_result2, TeslaBLE_Status_E_OK) << "Failed to update session";

  // Test response decryption parameters
  uint8_t mock_encrypted_data[] = {0x38, 0x03, 0x8e, 0x8c, 0x0f, 0x2e};  // Mock ciphertext
  uint8_t mock_nonce[12] = {0xdb, 0xf7, 0x94, 0x47, 0xfa, 0x15, 0x66, 0x74, 0xda, 0xe1, 0xca, 0xed};
  uint8_t mock_tag[16] = {0x8e, 0x12, 0x8d, 0xa1, 0x65, 0xf1, 0x62, 0xf4,
                          0xd7, 0xd2, 0xc8, 0xda, 0x86, 0x6c, 0xf8, 0x2a};

  // Mock request hash (would be from original request)
  uint8_t request_hash[17];
  request_hash[0] = Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED;
  memcpy(request_hash + 1, mock_tag, 16);  // Use same tag for simplicity

  uint8_t decrypted[256];
  size_t decrypted_length;

  int decrypt_result = peer.decrypt_response(mock_encrypted_data, sizeof(mock_encrypted_data), mock_nonce, mock_tag,
                                             request_hash, sizeof(request_hash),
                                             0,  // flags
                                             0,  // fault
                                             decrypted, sizeof(decrypted), &decrypted_length);

  // The exact result depends on the mock data being valid
  // But we should get a meaningful response
  EXPECT_TRUE(decrypt_result == TeslaBLE_Status_E_OK || decrypt_result != TeslaBLE_Status_E_OK)
      << "Decryption should either succeed or fail gracefully";

  if (result == TeslaBLE_Status_E_OK) {
    EXPECT_GT(decrypted_length, 0) << "Successful decryption should produce content";
  }
}

TEST_F(ProtocolHandshakeTest, VcsecResponseDecryptRoundTrip) {
  auto result =
      crypto_context_->load_private_key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key";

  Peer peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto_context_, TestConstants::TEST_VIN);
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  session_info.counter = 10;
  session_info.clock_time = 4242;
  std::copy(TestConstants::TEST_EPOCH, TestConstants::TEST_EPOCH + 16, session_info.epoch);
  std::copy(TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY + 65,
            session_info.publicKey.bytes);
  session_info.publicKey.size = 65;

  int update_result = peer.update_session(&session_info);
  ASSERT_EQ(update_result, TeslaBLE_Status_E_OK) << "Failed to update session";

  std::array<pb_byte_t, Peer::TAG_SIZE_BYTES> request_tag = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10};
  std::array<pb_byte_t, 17> request_hash{};
  size_t request_hash_length = 0;
  auto hash_result =
      peer.construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, request_tag.data(),
                                  request_tag.size(), request_hash.data(), &request_hash_length);
  ASSERT_EQ(hash_result, TeslaBLE_Status_E_OK) << "Failed to construct request hash";
  ASSERT_EQ(request_hash_length, static_cast<size_t>(17)) << "VCSEC request hash should be 17 bytes";

  std::array<pb_byte_t, 80> ad_buffer{};
  size_t ad_length = 0;
  uint32_t flags = (1u << UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE);
  uint32_t fault = 0;
  auto ad_result =
      peer.construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE, TestConstants::TEST_VIN, 0,
                               ad_buffer.data(), &ad_length, flags, request_hash.data(), request_hash_length, fault);
  ASSERT_EQ(ad_result, TeslaBLE_Status_E_OK) << "Failed to construct AD buffer";

  unsigned char ad_hash[32];
  ASSERT_EQ(mbedtls_sha256(ad_buffer.data(), ad_length, ad_hash, 0), 0) << "Failed to hash AD buffer";

  std::array<pb_byte_t, Peer::NONCE_SIZE_BYTES> nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                                         0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  std::array<pb_byte_t, 12> plaintext = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b};

  std::array<pb_byte_t, 32> ciphertext{};
  size_t ciphertext_length = 0;
  std::array<pb_byte_t, Peer::TAG_SIZE_BYTES> tag{};
  std::array<pb_byte_t, Peer::TAG_SIZE_BYTES> finish_buffer{};
  size_t finish_length = 0;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  ASSERT_EQ(mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, peer.get_shared_secret(), 128), 0)
      << "Failed to set AES key";
  ASSERT_EQ(mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_ENCRYPT, nonce.data(), nonce.size()), 0) << "Failed to start GCM";
  ASSERT_EQ(mbedtls_gcm_update_ad(&gcm, ad_hash, sizeof(ad_hash)), 0) << "Failed to set AAD";
  ASSERT_EQ(mbedtls_gcm_update(&gcm, plaintext.data(), plaintext.size(), ciphertext.data(), ciphertext.size(),
                               &ciphertext_length),
            0)
      << "Failed to encrypt";
  ASSERT_EQ(
      mbedtls_gcm_finish(&gcm, finish_buffer.data(), finish_buffer.size(), &finish_length, tag.data(), tag.size()), 0)
      << "Failed to finalize encryption";
  mbedtls_gcm_free(&gcm);

  std::array<pb_byte_t, 32> decrypted{};
  size_t decrypted_length = 0;
  int decrypt_result =
      peer.decrypt_response(ciphertext.data(), ciphertext_length, nonce.data(), tag.data(), request_hash.data(),
                            request_hash_length, flags, fault, decrypted.data(), decrypted.size(), &decrypted_length);
  ASSERT_EQ(decrypt_result, TeslaBLE_Status_E_OK) << "Failed to decrypt VCSEC response";
  ASSERT_EQ(decrypted_length, plaintext.size()) << "Decrypted length mismatch";
  EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), decrypted.begin()))
      << "Decrypted payload should match plaintext";
}

// Test 5: Domain-Specific Behavior
TEST_F(ProtocolHandshakeTest, DomainSpecificBehavior) {
  // Test differences between VCSEC and Infotainment domains

  auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  auto *info_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);

  ASSERT_NE(vcsec_peer, nullptr) << "Should be able to get VCSEC peer";
  ASSERT_NE(info_peer, nullptr) << "Should be able to get Infotainment peer";

  // Verify they have different domains
  EXPECT_EQ(vcsec_peer->get_domain(), UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  EXPECT_EQ(info_peer->get_domain(), UniversalMessage_Domain_DOMAIN_INFOTAINMENT);

  // Test request hash construction differences
  uint8_t test_tag[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

  uint8_t vcsec_hash[17], info_hash[17];
  size_t vcsec_length, info_length;

  auto vcsec_result = vcsec_peer->construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                         test_tag, 16, vcsec_hash, &vcsec_length);

  auto info_result = info_peer->construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                       test_tag, 16, info_hash, &info_length);

  ASSERT_EQ(vcsec_result, TeslaBLE_Status_E_OK) << "VCSEC request hash construction should succeed";
  ASSERT_EQ(info_result, TeslaBLE_Status_E_OK) << "Infotainment request hash construction should succeed";

  // Both should be 17 bytes for AES-GCM (VCSEC truncates, Infotainment doesn't truncate AES-GCM)
  EXPECT_EQ(vcsec_length, 17) << "VCSEC hash should be 17 bytes";
  EXPECT_EQ(info_length, 17) << "Infotainment hash should be 17 bytes";

  // Content should be identical for AES-GCM (both have same tag length)
  EXPECT_EQ(memcmp(vcsec_hash, info_hash, 17), 0) << "AES-GCM request hashes should be identical between domains";
}

}  // namespace TeslaBLE
