#include <gtest/gtest.h>
#include <client.h>
#include <errors.h>
#include <universal_message.pb.h>
#include <algorithm>
#include <cstring>
#include <vector>
#include "test_constants.h"

using namespace TeslaBLE;

class ErrorHandlingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = std::make_unique<Client>();
    client_->set_vin(TestConstants::TEST_VIN);
  }

  void TearDown() override { client_.reset(); }

  std::unique_ptr<Client> client_;
};

// Helper function to get all error codes as a vector
std::vector<TeslaBLE_Status_E> get_all_error_codes() {
  auto error_map = get_all_error_codes_and_strings();
  std::vector<TeslaBLE_Status_E> codes;
  codes.reserve(error_map.size());
  for (const auto &pair : error_map) {
    codes.push_back(pair.first);
  }
  return codes;
}

TEST_F(ErrorHandlingTest, ErrorCodeToStringMapping) {
  auto error_map = get_all_error_codes_and_strings();

  // Test all error codes have proper string representations
  for (const auto &pair : error_map) {
    EXPECT_STREQ(teslable_status_to_string(pair.first), pair.second.c_str())
        << "Error code " << static_cast<int>(pair.first) << " should map to '" << pair.second << "'";
  }
}

TEST_F(ErrorHandlingTest, UnknownErrorCode) {
  // Test unknown error code returns "ERROR_UNKNOWN"
  auto error_map = get_all_error_codes_and_strings();
  int max_value = 0;
  for (const auto &pair : error_map) {
    max_value = std::max(max_value, static_cast<int>(pair.first));
  }
  int invalid_value = max_value + 1;
  const char *result = teslable_status_to_string(static_cast<TeslaBLE_Status_E>(invalid_value));
  EXPECT_STREQ(result, "ERROR_UNKNOWN");

  // Explicitly verify the function is called and result is not null
  EXPECT_NE(result, nullptr);
  EXPECT_GT(strlen(result), 0);
}

TEST_F(ErrorHandlingTest, AllErrorCodesAreMapped) {
  auto all_codes = get_all_error_codes();

  // Ensure every error code has a non-null string representation
  for (auto code : all_codes) {
    const char *result = teslable_status_to_string(code);
    EXPECT_NE(result, nullptr) << "Error code " << static_cast<int>(code) << " should have string representation";
    EXPECT_GT(strlen(result), 0) << "Error code " << static_cast<int>(code) << " should have non-empty string";
    EXPECT_STRNE(result, "ERROR_UNKNOWN")
        << "Error code " << static_cast<int>(code) << " should not map to ERROR_UNKNOWN";
  }
}

TEST_F(ErrorHandlingTest, BuildMessageWithoutPrivateKey) {
  pb_byte_t buffer[500];
  size_t length = 0;

  // Try to build messages without loading a private key first
  int32_t amps = 12;
  auto result1 = client_->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_NE(result1, TeslaBLE_Status_E_OK) << "Building message without private key should fail";

  int32_t percent = 80;
  auto result2 = client_->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_chargingSetLimitAction_tag, &percent);
  EXPECT_NE(result2, TeslaBLE_Status_E_OK) << "Building charging limit message without private key should fail";

  bool hvac_on = true;
  auto result3 = client_->build_car_server_vehicle_action_message(buffer, &length,
                                                                  CarServer_VehicleAction_hvacAutoAction_tag, &hvac_on);
  EXPECT_NE(result3, TeslaBLE_Status_E_OK) << "Building HVAC message without private key should fail";
}

TEST_F(ErrorHandlingTest, BuildMessageWithNullParameters) {
  pb_byte_t buffer[500];
  size_t length = 0;

  // Test with null buffer
  int32_t amps = 12;
  auto result1 = client_->build_car_server_vehicle_action_message(
      nullptr, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_EQ(result1, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null buffer should return INVALID_PARAMS";

  // Test with null length pointer
  auto result2 = client_->build_car_server_vehicle_action_message(
      buffer, nullptr, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_EQ(result2, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null length pointer should return INVALID_PARAMS";

  // Test with both null
  auto result3 = client_->build_car_server_vehicle_action_message(
      nullptr, nullptr, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_EQ(result3, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Both null should return INVALID_PARAMS";
}

TEST_F(ErrorHandlingTest, ParseMessageWithNullParameters) {
  UniversalMessage_RoutableMessage message;
  pb_byte_t buffer[100];

  // Test parseUniversalMessage with null buffer
  auto result1 = client_->parse_universal_message(nullptr, 10, &message);
  EXPECT_EQ(result1, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null input buffer should return INVALID_PARAMS";

  // Test parseUniversalMessage with null output
  auto result2 = client_->parse_universal_message(buffer, sizeof(buffer), nullptr);
  EXPECT_EQ(result2, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null output should return INVALID_PARAMS";

  // Test parseUniversalMessage with zero length
  auto result3 = client_->parse_universal_message(buffer, 0, &message);
  EXPECT_EQ(result3, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Zero length should return INVALID_PARAMS";
}

TEST_F(ErrorHandlingTest, ParseSessionInfoWithNullParameters) {
  UniversalMessage_RoutableMessage_session_info_t session_info;
  Signatures_SessionInfo output;

  // Initialize session_info with some data
  session_info.size = 10;
  memset(session_info.bytes, 0, 10);

  // Test parsePayloadSessionInfo with null input
  auto result1 = client_->parse_payload_session_info(nullptr, &output);
  EXPECT_EQ(result1, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null input should return INVALID_PARAMS";

  // Test parsePayloadSessionInfo with null output
  auto result2 = client_->parse_payload_session_info(&session_info, nullptr);
  EXPECT_EQ(result2, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null output should return INVALID_PARAMS";
}

TEST_F(ErrorHandlingTest, PrivateKeyOperationsWithoutKey) {
  pb_byte_t buffer[300];
  size_t length = 0;

  // Try to get private key without having one loaded
  auto result = client_->get_private_key(buffer, sizeof(buffer), &length);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Getting private key without loading one should fail";
}

TEST_F(ErrorHandlingTest, EdgeCaseFunctionCalls) {
  pb_byte_t buffer[500];
  size_t length = 0;

  // Test various boundary conditions
  pb_byte_t small_buffer[1];
  size_t small_length = 0;
  int32_t amps = 12;
  auto result1 = client_->build_car_server_vehicle_action_message(
      small_buffer, &small_length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_NE(result1, TeslaBLE_Status_E_OK) << "Building message with insufficient buffer should fail";

  // Test with boundary charge amounts
  int32_t zero_amps = 0;
  auto result2 = client_->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &zero_amps);
  EXPECT_NE(result2, TeslaBLE_Status_E_OK) << "Building message with 0 amps should fail";

  int32_t high_percent = 101;
  auto result3 = client_->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_chargingSetLimitAction_tag, &high_percent);
  EXPECT_NE(result3, TeslaBLE_Status_E_OK) << "Building message with >100% limit should fail";

  // Test buildUniversalMessageWithPayload without valid payload
  pb_byte_t output_buffer[300];
  size_t output_length = 0;
  pb_byte_t empty_payload[1] = {0};
  auto result4 = client_->build_universal_message_with_payload(
      empty_payload, 0, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, output_buffer, &output_length);
  EXPECT_NE(result4, TeslaBLE_Status_E_OK) << "Building universal message with empty payload should fail";
}
