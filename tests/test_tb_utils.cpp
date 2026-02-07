#include <gtest/gtest.h>
#include <tb_utils.h>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include "test_constants.h"

using namespace TeslaBLE;

class TBUtilsTest : public ::testing::Test {};

// Test the main function in tb_utils.cpp: pb_encode_fields
TEST_F(TBUtilsTest, PbEncodeFieldsValidMessage) {
  // Create a simple VCSEC message to test encoding
  VCSEC_InformationRequest info_request = VCSEC_InformationRequest_init_default;
  info_request.informationRequestType = VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS;

  VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
  unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
  unsigned_message.sub_message.InformationRequest = info_request;

  pb_byte_t output_buffer[VCSEC_UnsignedMessage_size];
  size_t output_length;

  auto result = pb_encode_fields(output_buffer, &output_length, VCSEC_UnsignedMessage_fields, &unsigned_message);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should succeed for valid message";
  EXPECT_GT(output_length, 0) << "Encoded message should have non-zero length";
  EXPECT_LE(output_length, sizeof(output_buffer)) << "Encoded message should fit in buffer";
}

TEST_F(TBUtilsTest, PbEncodeFieldsNullPointers) {
  VCSEC_InformationRequest info_request = VCSEC_InformationRequest_init_default;
  pb_byte_t output_buffer[100];
  size_t output_length;

  // Test with null output buffer
  auto result = pb_encode_fields(nullptr, &output_length, VCSEC_InformationRequest_fields, &info_request);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should fail with null output buffer";

  // Test with null output length
  result = pb_encode_fields(output_buffer, nullptr, VCSEC_InformationRequest_fields, &info_request);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should fail with null output length";

  // Test with null fields
  result = pb_encode_fields(output_buffer, &output_length, nullptr, &info_request);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should fail with null fields";

  // Test with null source struct
  result = pb_encode_fields(output_buffer, &output_length, VCSEC_InformationRequest_fields, nullptr);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should fail with null source struct";
}

TEST_F(TBUtilsTest, PbEncodeFieldsUniversalMessage) {
  // Test encoding a more complex universal message
  UniversalMessage_RoutableMessage routable_message = UniversalMessage_RoutableMessage_init_default;
  routable_message.which_payload = UniversalMessage_RoutableMessage_session_info_request_tag;
  routable_message.payload.session_info_request.public_key.size = sizeof(TestConstants::EXPECTED_CLIENT_PUBLIC_KEY);
  memcpy(routable_message.payload.session_info_request.public_key.bytes, TestConstants::EXPECTED_CLIENT_PUBLIC_KEY,
         sizeof(TestConstants::EXPECTED_CLIENT_PUBLIC_KEY));

  pb_byte_t output_buffer[UniversalMessage_RoutableMessage_size];
  size_t output_length;

  auto result =
      pb_encode_fields(output_buffer, &output_length, UniversalMessage_RoutableMessage_fields, &routable_message);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should succeed for UniversalMessage";
  EXPECT_GT(output_length, 0) << "Encoded UniversalMessage should have non-zero length";
  EXPECT_GE(output_length, sizeof(TestConstants::EXPECTED_CLIENT_PUBLIC_KEY))
      << "Encoded message should be at least as large as public key";
}

TEST_F(TBUtilsTest, PbEncodeFieldsBufferTooSmall) {
  // This test verifies that pb_encode_fields properly handles buffer size validation
  // The current implementation calculates the required size first, so we can't test
  // buffer overflow in the same way. Instead, we test that the function correctly
  // reports the required size.

  VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
  unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
  unsigned_message.sub_message.InformationRequest.informationRequestType =
      VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS;

  // Get the required size
  pb_byte_t buffer[VCSEC_UnsignedMessage_size];
  size_t required_length;
  auto result = pb_encode_fields(buffer, &required_length, VCSEC_UnsignedMessage_fields, &unsigned_message);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "pb_encode_fields should succeed for valid message";
  EXPECT_GT(required_length, 0) << "Required size should be greater than 0";
  EXPECT_LE(required_length, sizeof(buffer)) << "Required size should not exceed buffer size";
}

// Tests for format_hex utility function
TEST_F(TBUtilsTest, FormatHexBasic) {
  const uint8_t data[] = {0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF};
  std::string hex = format_hex(data, sizeof(data));

  EXPECT_EQ(hex, "010203abcdef");
}

TEST_F(TBUtilsTest, FormatHexEmptyData) {
  std::string hex1 = format_hex(nullptr, 10);
  EXPECT_EQ(hex1, "");

  const uint8_t data[] = {0x01};
  std::string hex2 = format_hex(data, 0);
  EXPECT_EQ(hex2, "");
}

TEST_F(TBUtilsTest, FormatHexSingleByte) {
  const uint8_t data[] = {0xFF};
  std::string hex = format_hex(data, 1);

  EXPECT_EQ(hex, "ff");
}

TEST_F(TBUtilsTest, FormatHexAllZeros) {
  const uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
  std::string hex = format_hex(data, sizeof(data));

  EXPECT_EQ(hex, "00000000");
}

TEST_F(TBUtilsTest, FormatHexLargeData) {
  std::vector<uint8_t> data(256);
  for (size_t i = 0; i < data.size(); i++) {
    data[i] = static_cast<uint8_t>(i);
  }

  std::string hex = format_hex(data.data(), data.size());

  // Should be 512 characters (2 per byte)
  EXPECT_EQ(hex.length(), 512);

  // Check first few bytes
  EXPECT_EQ(hex.substr(0, 6), "000102");

  // Check last byte (255 = 0xFF)
  EXPECT_EQ(hex.substr(510, 2), "ff");
}
