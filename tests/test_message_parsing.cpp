#include <gtest/gtest.h>
#include <client.h>
#include <universal_message.pb.h>
#include <signatures.pb.h>
#include <car_server.pb.h>
#include <algorithm>
#include <array>
#include <ranges>
#include <cstring>
#include "tb_utils.h"
#include "test_constants.h"

using namespace TeslaBLE;

// Mock received message from VCSEC (from main.cpp)
namespace {
constexpr size_t K_MOCK_MESSAGE_SIZE = 177;

std::array<pb_byte_t, K_MOCK_MESSAGE_SIZE> copy_mock_message(const pb_byte_t (&data)[K_MOCK_MESSAGE_SIZE]) {
  std::array<pb_byte_t, K_MOCK_MESSAGE_SIZE> copy{};
  std::ranges::copy(data, copy.begin());
  return copy;
}
}  // namespace

class MessageParsingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = std::make_unique<Client>();
    client_->set_vin(TestConstants::TEST_VIN);

    // Load private key for testing
    auto status =
        client_->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                  strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    ASSERT_EQ(status, TeslaBLE_Status_E_OK) << "Failed to load private key for testing";
  }

  void TearDown() override { client_.reset(); }

  std::unique_ptr<Client> client_;
};

TEST_F(MessageParsingTest, ParseValidVCSECUniversalMessage) {
  auto vcsec_message = copy_mock_message(TestConstants::MOCK_VCSEC_MESSAGE);
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;

  auto result = client_->parse_universal_message(vcsec_message.data(), vcsec_message.size(), &received_message);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Parsing valid VCSEC universal message should succeed";

  // Basic validation of parsed message
  EXPECT_TRUE(received_message.has_to_destination) << "Message should have to_destination";
  EXPECT_TRUE(received_message.has_from_destination) << "Message should have from_destination";
}

TEST_F(MessageParsingTest, ParseValidInfotainmentUniversalMessage) {
  auto infotainment_message = copy_mock_message(TestConstants::MOCK_INFOTAINMENT_MESSAGE);
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;

  auto result =
      client_->parse_universal_message(infotainment_message.data(), infotainment_message.size(), &received_message);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Parsing valid Infotainment universal message should succeed";

  // Basic validation of parsed message
  EXPECT_TRUE(received_message.has_to_destination) << "Message should have to_destination";
  EXPECT_TRUE(received_message.has_from_destination) << "Message should have from_destination";
}

TEST_F(MessageParsingTest, ParseInvalidUniversalMessage) {
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;

  // Test with invalid data
  pb_byte_t invalid_data[] = {0x00, 0x01, 0x02, 0x03};
  auto result = client_->parse_universal_message(invalid_data, sizeof(invalid_data), &received_message);

  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Parsing invalid universal message should fail";
}

TEST_F(MessageParsingTest, ParseEmptyUniversalMessage) {
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;

  auto result = client_->parse_universal_message(nullptr, 0, &received_message);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Parsing empty/null universal message should fail";
}

TEST_F(MessageParsingTest, ParseSessionInfoFromVCSECMessage) {
  // First parse the universal message
  auto vcsec_message = copy_mock_message(TestConstants::MOCK_VCSEC_MESSAGE);
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  auto parse_result = client_->parse_universal_message(vcsec_message.data(), vcsec_message.size(), &received_message);
  ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse universal message";

  // Now parse the session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  auto session_result = client_->parse_payload_session_info(&received_message.payload.session_info, &session_info);

  EXPECT_EQ(session_result, TeslaBLE_Status_E_OK) << "Parsing session info from VCSEC message should succeed";

  // Basic validation
  EXPECT_GT(session_info.publicKey.size, 0) << "Session info should have a public key";
  EXPECT_GE(session_info.counter, 0) << "Session info should have a valid counter";
}

TEST_F(MessageParsingTest, ParseSessionInfoFromInfotainmentMessage) {
  // First parse the universal message
  auto infotainment_message = copy_mock_message(TestConstants::MOCK_INFOTAINMENT_MESSAGE);
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  auto parse_result =
      client_->parse_universal_message(infotainment_message.data(), infotainment_message.size(), &received_message);
  ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse universal message";

  // Now parse the session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  auto session_result = client_->parse_payload_session_info(&received_message.payload.session_info, &session_info);

  EXPECT_EQ(session_result, TeslaBLE_Status_E_OK) << "Parsing session info from Infotainment message should succeed";

  // Basic validation
  EXPECT_GT(session_info.publicKey.size, 0) << "Session info should have a public key";
  EXPECT_GE(session_info.counter, 0) << "Session info should have a valid counter";
}

TEST_F(MessageParsingTest, ParseMessageWithNullOutput) {
  auto vcsec_message = copy_mock_message(TestConstants::MOCK_VCSEC_MESSAGE);
  auto result = client_->parse_universal_message(vcsec_message.data(), vcsec_message.size(), nullptr);

  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Parsing message with null output should fail";
}

TEST_F(MessageParsingTest, ParseSessionInfoWithNullOutput) {
  // First parse a valid universal message
  auto vcsec_message = copy_mock_message(TestConstants::MOCK_VCSEC_MESSAGE);
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  auto parse_result = client_->parse_universal_message(vcsec_message.data(), vcsec_message.size(), &received_message);
  ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse universal message";

  // Try to parse session info with null output
  auto session_result = client_->parse_payload_session_info(&received_message.payload.session_info, nullptr);

  EXPECT_NE(session_result, TeslaBLE_Status_E_OK) << "Parsing session info with null output should fail";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponsePlaintext) {
  // Create a minimal valid CarServer Response with just actionStatus
  // Based on protobuf wire format: field 1 (actionStatus) with result = 0 (OK)
  pb_byte_t mock_response_data[] = {
      0x0A, 0x02, 0x08, 0x00  // actionStatus { result: OPERATIONSTATUS_OK }
  };

  // Create input buffer structure
  UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t input_buffer;
  input_buffer.size = sizeof(mock_response_data);
  memcpy(input_buffer.bytes, mock_response_data, sizeof(mock_response_data));

  // Parse the response (plaintext, no encryption)
  CarServer_Response parsed_response = CarServer_Response_init_default;
  Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;

  auto result = client_->parse_payload_car_server_response(&input_buffer, &signature_data,
                                                           0,  // which_sub_sigData = 0 means plaintext
                                                           UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE, 0,
                                                           &parsed_response);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Parsing plaintext CarServer response should succeed";
  EXPECT_TRUE(parsed_response.has_actionStatus) << "Parsed response should have action status";
  EXPECT_EQ(parsed_response.actionStatus.result, CarServer_OperationStatus_E_OPERATIONSTATUS_OK)
      << "Action status should be OK";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponseInvalidData) {
  // Create invalid protobuf data
  UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t input_buffer;
  pb_byte_t invalid_data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02};
  input_buffer.size = sizeof(invalid_data);
  memcpy(input_buffer.bytes, invalid_data, sizeof(invalid_data));

  CarServer_Response parsed_response = CarServer_Response_init_default;
  Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;

  auto result = client_->parse_payload_car_server_response(&input_buffer, &signature_data,
                                                           0,  // plaintext
                                                           UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE, 0,
                                                           &parsed_response);

  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Parsing invalid CarServer response data should fail";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponseEdgeCases) {
  CarServer_Response parsed_response = CarServer_Response_init_default;
  Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;

  // Test with buffer containing only invalid protobuf data
  UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t invalid_buffer;
  pb_byte_t invalid_data[] = {0xFF, 0xFF, 0xFF};  // Invalid protobuf wire format
  invalid_buffer.size = sizeof(invalid_data);
  memcpy(invalid_buffer.bytes, invalid_data, sizeof(invalid_data));

  auto result = client_->parse_payload_car_server_response(&invalid_buffer, &signature_data, 0,
                                                           UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE, 0,
                                                           &parsed_response);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Parsing with invalid protobuf data should fail";

  // Test with truncated valid data
  UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t truncated_buffer;
  pb_byte_t truncated_data[] = {0x0A, 0x02};  // Incomplete actionStatus field
  truncated_buffer.size = sizeof(truncated_data);
  memcpy(truncated_buffer.bytes, truncated_data, sizeof(truncated_data));

  result = client_->parse_payload_car_server_response(&truncated_buffer, &signature_data, 0,
                                                      UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE, 0,
                                                      &parsed_response);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Parsing with truncated data should fail";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponseChargeLimitReasonOneof) {
  CarServer_Response response = CarServer_Response_init_default;
  response.which_response_msg = CarServer_Response_vehicleData_tag;
  response.response_msg.vehicleData.has_charge_state = true;

  auto &charge_state = response.response_msg.vehicleData.charge_state;
  charge_state.which_optional_charge_limit_reason = CarServer_ChargeState_charge_limit_reason_tag;
  charge_state.optional_charge_limit_reason.charge_limit_reason =
      CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonEvse;

  pb_byte_t encoded_response[512];
  size_t encoded_length = sizeof(encoded_response);
  auto encode_status = pb_encode_fields(encoded_response, &encoded_length, CarServer_Response_fields, &response);
  ASSERT_EQ(encode_status, TeslaBLE_Status_E_OK) << "Encoding CarServer response should succeed";

  UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t input_buffer;
  input_buffer.size = encoded_length;
  memcpy(input_buffer.bytes, encoded_response, encoded_length);

  CarServer_Response parsed_response = CarServer_Response_init_default;
  Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
  auto parse_status = client_->parse_payload_car_server_response(
      &input_buffer, &signature_data, 0, UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE, 0, &parsed_response);

  ASSERT_EQ(parse_status, TeslaBLE_Status_E_OK) << "Parsing CarServer response should succeed";
  ASSERT_EQ(parsed_response.which_response_msg, CarServer_Response_vehicleData_tag);
  ASSERT_TRUE(parsed_response.response_msg.vehicleData.has_charge_state);
  EXPECT_EQ(parsed_response.response_msg.vehicleData.charge_state.which_optional_charge_limit_reason,
            CarServer_ChargeState_charge_limit_reason_tag);
  EXPECT_EQ(parsed_response.response_msg.vehicleData.charge_state.optional_charge_limit_reason.charge_limit_reason,
            CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonEvse);
}
