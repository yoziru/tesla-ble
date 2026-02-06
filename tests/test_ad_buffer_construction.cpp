#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <cstring>

#include "peer.h"
#include "crypto_context.h"
#include "errors.h"
#include "signatures.pb.h"
#include "universal_message.pb.h"

using TeslaBLE::CryptoContext;
using TeslaBLE::Peer;
using TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
using TeslaBLE::TeslaBLE_Status_E_OK;

class ADBufferConstructionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create crypto context
    crypto_context_ = std::make_shared<CryptoContext>();

    test_vin_ = "1HGCM82633A004352";

    // Set up test epoch (16 bytes)
    test_epoch_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    test_counter_ = 12345;

    // Create peers for different domains
    vcsec_peer_ = std::make_unique<Peer>(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto_context_, test_vin_);
    infotainment_peer_ =
        std::make_unique<Peer>(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context_, test_vin_);

    // Initialize peers with test data
    vcsec_peer_->set_epoch(test_epoch_.data());
    vcsec_peer_->set_counter(test_counter_);

    infotainment_peer_->set_epoch(test_epoch_.data());
    infotainment_peer_->set_counter(test_counter_);
  }

  std::shared_ptr<CryptoContext> crypto_context_;
  std::unique_ptr<Peer> vcsec_peer_;
  std::unique_ptr<Peer> infotainment_peer_;
  std::string test_vin_;
  std::vector<uint8_t> test_epoch_;
  uint32_t test_counter_;
};

TEST_F(ADBufferConstructionTest, RequestMetadataFormat) {
  pb_byte_t ad_buffer[256];
  size_t ad_length;
  uint32_t expires_at = 2655;

  // Test request format
  auto result = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                 test_vin_.c_str(), expires_at, ad_buffer, &ad_length,
                                                 0,  // flags = 0 for request
                                                 nullptr, 0);

  ASSERT_EQ(result, TeslaBLE_Status_E_OK);
  ASSERT_GT(ad_length, 0);

  // Verify TLV structure for request
  size_t i = 0;

  // Signature type
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_SIGNATURE_TYPE);
  EXPECT_EQ(ad_buffer[i + 1], 0x01);
  EXPECT_EQ(ad_buffer[i + 2], Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED);
  i += 3;

  // Domain
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_DOMAIN);
  EXPECT_EQ(ad_buffer[i + 1], 0x01);
  EXPECT_EQ(ad_buffer[i + 2], UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  i += 3;

  // VIN
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_PERSONALIZATION);
  EXPECT_EQ(ad_buffer[i + 1], test_vin_.length());
  i += 2 + test_vin_.length();

  // Epoch
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_EPOCH);
  i += 2 + ad_buffer[i + 1];

  // Expires at
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_EXPIRES_AT);
  EXPECT_EQ(ad_buffer[i + 1], 0x04);
  i += 2 + 4;

  // Counter
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_COUNTER);
  EXPECT_EQ(ad_buffer[i + 1], 0x04);
  i += 2 + 4;

  // Flags should NOT be present for request with flags=0
  EXPECT_NE(ad_buffer[i], Signatures_Tag_TAG_FLAGS);

  // Terminal byte
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_END);
}

TEST_F(ADBufferConstructionTest, ResponseMetadataFormat) {
  pb_byte_t ad_buffer[256];
  size_t ad_length;
  uint32_t expires_at = 2655;
  // BLE uses AES-GCM encryption with 16-byte tags
  // Request hash: 1 auth method byte + 16-byte AES-GCM tag = 17 bytes
  uint8_t request_hash[17] = {Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                              0x00,
                              0x01,
                              0x02,
                              0x03,
                              0x04,
                              0x05,
                              0x06,
                              0x07,
                              0x08,
                              0x09,
                              0x0A,
                              0x0B,
                              0x0C,
                              0x0D,
                              0x0E,
                              0x0F};

  // Test response format
  auto result = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE,
                                                 test_vin_.c_str(), expires_at, ad_buffer, &ad_length,
                                                 0,  // flags
                                                 request_hash, sizeof(request_hash),
                                                 42  // fault code
  );

  ASSERT_EQ(result, TeslaBLE_Status_E_OK);
  ASSERT_GT(ad_length, 0);

  // Verify TLV structure for response
  size_t i = 0;

  // Signature type
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_SIGNATURE_TYPE);
  EXPECT_EQ(ad_buffer[i + 1], 0x01);
  EXPECT_EQ(ad_buffer[i + 2], Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE);
  i += 3;

  // Domain
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_DOMAIN);
  EXPECT_EQ(ad_buffer[i + 1], 0x01);
  i += 3;

  // VIN
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_PERSONALIZATION);
  i += 2 + ad_buffer[i + 1];

  // Counter (responses do not include epoch/expires_at)
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_COUNTER);
  i += 2 + ad_buffer[i + 1];

  // Flags - should always be present for responses
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_FLAGS);
  i += 2 + ad_buffer[i + 1];

  // Request hash
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_REQUEST_HASH);
  i += 2 + ad_buffer[i + 1];

  // Fault
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_FAULT);
  i += 2 + ad_buffer[i + 1];

  // Terminal byte
  EXPECT_EQ(ad_buffer[i], Signatures_Tag_TAG_END);
}

TEST_F(ADBufferConstructionTest, FlagsConditionalInclusion) {
  pb_byte_t ad_buffer_no_flags[256];
  pb_byte_t ad_buffer_with_flags[256];
  size_t ad_length_no_flags, ad_length_with_flags;
  uint32_t expires_at = 2655;

  // Test with flags = 0 (should NOT be included for requests)
  auto result1 =
      vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, test_vin_.c_str(),
                                       expires_at, ad_buffer_no_flags, &ad_length_no_flags,
                                       0,  // flags = 0
                                       nullptr, 0);

  // Test with flags = 1 (should be included)
  auto result2 =
      vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, test_vin_.c_str(),
                                       expires_at, ad_buffer_with_flags, &ad_length_with_flags,
                                       1,  // flags = 1
                                       nullptr, 0);

  ASSERT_EQ(result1, TeslaBLE_Status_E_OK);
  ASSERT_EQ(result2, TeslaBLE_Status_E_OK);

  // Length with flags should be longer
  EXPECT_GT(ad_length_with_flags, ad_length_no_flags);

  // Check that flags field is not in no_flags buffer (parse TLV structure properly)
  bool flags_found_in_no_flags = false;
  size_t pos = 0;
  while (pos < ad_length_no_flags) {
    uint8_t tag = ad_buffer_no_flags[pos];
    if (tag == 0xFF) {
      break;  // Terminal byte
    }
    if (tag == Signatures_Tag_TAG_FLAGS) {
      flags_found_in_no_flags = true;
      break;
    }
    uint8_t length = ad_buffer_no_flags[pos + 1];
    pos += 2 + length;
  }
  ASSERT_FALSE(flags_found_in_no_flags);

  // Check that flags field is in with_flags buffer
  bool flags_found_in_with_flags = false;
  pos = 0;
  while (pos < ad_length_with_flags) {
    uint8_t tag = ad_buffer_with_flags[pos];
    if (tag == 0xFF) {
      break;  // Terminal byte
    }
    if (tag == Signatures_Tag_TAG_FLAGS) {
      flags_found_in_with_flags = true;
      break;
    }
    uint8_t length = ad_buffer_with_flags[pos + 1];
    pos += 2 + length;
  }
  ASSERT_TRUE(flags_found_in_with_flags);
}

TEST_F(ADBufferConstructionTest, ResponseAlwaysIncludesFlags) {
  pb_byte_t ad_buffer[256];
  size_t ad_length;
  uint32_t expires_at = 2655;
  // BLE uses AES-GCM encryption with 16-byte tags
  // Request hash: 1 auth method byte + 16-byte AES-GCM tag = 17 bytes
  uint8_t request_hash[17] = {0};

  // Test response format - flags should always be included even if 0
  auto result = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE,
                                                 test_vin_.c_str(), expires_at, ad_buffer, &ad_length,
                                                 0,  // flags = 0, but should still be included for responses
                                                 request_hash, sizeof(request_hash));

  ASSERT_EQ(result, TeslaBLE_Status_E_OK);

  // Check that flags field is present
  bool flags_found = false;
  for (size_t i = 0; i < ad_length - 1; ++i) {
    if (ad_buffer[i] == Signatures_Tag_TAG_FLAGS) {
      flags_found = true;
      break;
    }
  }
  ASSERT_TRUE(flags_found);
}

TEST_F(ADBufferConstructionTest, DifferentDomainsProduceDifferentBuffers) {
  pb_byte_t vcsec_buffer[256];
  pb_byte_t infotainment_buffer[256];
  size_t vcsec_length, infotainment_length;
  uint32_t expires_at = 2655;

  auto result1 =
      vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, test_vin_.c_str(),
                                       expires_at, vcsec_buffer, &vcsec_length, 0, nullptr, 0);

  auto result2 = infotainment_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                         test_vin_.c_str(), expires_at, infotainment_buffer,
                                                         &infotainment_length, 0, nullptr, 0);

  ASSERT_EQ(result1, TeslaBLE_Status_E_OK);
  ASSERT_EQ(result2, TeslaBLE_Status_E_OK);

  // Buffers should be different (different domain values)
  ASSERT_NE(std::memcmp(vcsec_buffer, infotainment_buffer, std::min(vcsec_length, infotainment_length)), 0);
}

TEST_F(ADBufferConstructionTest, TerminalByteAlwaysPresent) {
  pb_byte_t ad_buffer[256];
  size_t ad_length;
  uint32_t expires_at = 2655;

  auto result = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                 test_vin_.c_str(), expires_at, ad_buffer, &ad_length, 0, nullptr, 0);

  ASSERT_EQ(result, TeslaBLE_Status_E_OK);
  ASSERT_GT(ad_length, 0);

  // Last byte should be the terminal byte
  EXPECT_EQ(ad_buffer[ad_length - 1], Signatures_Tag_TAG_END);
}

TEST_F(ADBufferConstructionTest, InvalidParametersReturnError) {
  pb_byte_t ad_buffer[256];
  size_t ad_length;

  // Test null output buffer
  auto result1 = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                  test_vin_.c_str(), 2655, nullptr, &ad_length);
  EXPECT_EQ(result1, TeslaBLE_Status_E_ERROR_INVALID_PARAMS);

  // Test null output length
  auto result2 = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                  test_vin_.c_str(), 2655, ad_buffer, nullptr);
  EXPECT_EQ(result2, TeslaBLE_Status_E_ERROR_INVALID_PARAMS);

  // Test null VIN
  auto result3 = vcsec_peer_->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, nullptr,
                                                  2655, ad_buffer, &ad_length);
  EXPECT_EQ(result3, TeslaBLE_Status_E_ERROR_INVALID_PARAMS);
}

// Test request hash construction for both domains
TEST_F(ADBufferConstructionTest, RequestHashDomainDifferences) {
  pb_byte_t long_tag[32];  // 32-byte tag to test truncation
  for (int i = 0; i < 32; ++i) {
    long_tag[i] = i;
  }

  pb_byte_t vcsec_hash[64], infotainment_hash[64];
  size_t vcsec_hash_length, infotainment_hash_length;

  // Test VCSEC domain (should truncate to 17 bytes: 1 + 16)
  auto result1 = vcsec_peer_->construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                     long_tag, 32, vcsec_hash, &vcsec_hash_length);

  // Test INFOTAINMENT domain (should use full 33 bytes: 1 + 32)
  auto result2 =
      infotainment_peer_->construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, long_tag,
                                                 32, infotainment_hash, &infotainment_hash_length);

  EXPECT_EQ(result1, TeslaBLE_Status_E_OK);
  EXPECT_EQ(result2, TeslaBLE_Status_E_OK);

  // Verify domain-specific truncation behavior
  EXPECT_EQ(vcsec_hash_length, 17) << "VCSEC should truncate to 17 bytes";
  EXPECT_EQ(infotainment_hash_length, 33) << "INFOTAINMENT should use full length";

  // Both should start with the auth method byte
  EXPECT_EQ(vcsec_hash[0], Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED);
  EXPECT_EQ(infotainment_hash[0], Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED);

  // First 16 bytes of tag should be identical in both
  ASSERT_EQ(std::memcmp(vcsec_hash + 1, infotainment_hash + 1, 16), 0);

  // INFOTAINMENT should have the additional 16 bytes
  for (int i = 16; i < 32; ++i) {
    EXPECT_EQ(infotainment_hash[1 + i], i);
  }
}
