#include <gtest/gtest.h>
#include <client.h>
#include <errors.h>
#include <universal_message.pb.h>
#include <cstring>
#include <vector>
#include "test_constants.h"

using namespace TeslaBLE;

class ErrorHandlingTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<TeslaBLE::Client>();
        client->setVIN(TestConstants::TEST_VIN);
    }

    void TearDown() override {
        client.reset();
    }

    std::unique_ptr<TeslaBLE::Client> client;
};

TEST_F(ErrorHandlingTest, ErrorCodeToStringMapping) {
    // Test all error codes have proper string representations
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_OK), "OK");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_INTERNAL), "ERROR_INTERNAL");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_PB_ENCODING), "ERROR_PB_ENCODING");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_PB_DECODING), "ERROR_PB_DECODING");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED), "ERROR_PRIVATE_KEY_NOT_INITIALIZED");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_SESSION), "ERROR_INVALID_SESSION");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_ENCRYPT), "ERROR_ENCRYPT");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_DECRYPT), "ERROR_DECRYPT");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS), "ERROR_INVALID_PARAMS");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_CRYPTO), "ERROR_CRYPTO");
    EXPECT_STREQ(TeslaBLE::TeslaBLE_Status_to_string(TeslaBLE::TeslaBLE_Status_E_ERROR_COUNTER_REPLAY), "ERROR_COUNTER_REPLAY");
}

TEST_F(ErrorHandlingTest, UnknownErrorCode) {
    // Test unknown error code returns "ERROR_UNKNOWN"
    const char* result = TeslaBLE::TeslaBLE_Status_to_string(static_cast<TeslaBLE::TeslaBLE_Status_E>(999));
    EXPECT_STREQ(result, "ERROR_UNKNOWN");
    
    // Explicitly verify the function is called and result is not null
    EXPECT_NE(result, nullptr);
    EXPECT_GT(strlen(result), 0);
}

TEST_F(ErrorHandlingTest, AllErrorCodesAreMapped) {
    // Ensure every error code has a non-null string representation
    std::vector<TeslaBLE::TeslaBLE_Status_E> all_codes = {
        TeslaBLE::TeslaBLE_Status_E_OK,
        TeslaBLE::TeslaBLE_Status_E_ERROR_INTERNAL,
        TeslaBLE::TeslaBLE_Status_E_ERROR_PB_ENCODING,
        TeslaBLE::TeslaBLE_Status_E_ERROR_PB_DECODING,
        TeslaBLE::TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED,
        TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_SESSION,
        TeslaBLE::TeslaBLE_Status_E_ERROR_ENCRYPT,
        TeslaBLE::TeslaBLE_Status_E_ERROR_DECRYPT,
        TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS,
        TeslaBLE::TeslaBLE_Status_E_ERROR_CRYPTO,
        TeslaBLE::TeslaBLE_Status_E_ERROR_COUNTER_REPLAY
    };
    
    for (auto code : all_codes) {
        const char* result = TeslaBLE::TeslaBLE_Status_to_string(code);
        EXPECT_NE(result, nullptr) << "Error code " << static_cast<int>(code) << " should have string representation";
        EXPECT_GT(strlen(result), 0) << "Error code " << static_cast<int>(code) << " should have non-empty string";
    }
}

TEST_F(ErrorHandlingTest, BuildMessageWithoutPrivateKey) {
    pb_byte_t buffer[500];
    size_t length = 0;
    
    // Try to build messages without loading a private key first
    int32_t amps = 12;
    int result1 = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_NE(result1, 0) << "Building message without private key should fail";
    
    int32_t percent = 80;
    int result2 = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_chargingSetLimitAction_tag, &percent);
    EXPECT_NE(result2, 0) << "Building charging limit message without private key should fail";
    
    bool hvac_on = true;
    int result3 = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_hvacAutoAction_tag, &hvac_on);
    EXPECT_NE(result3, 0) << "Building HVAC message without private key should fail";
}

TEST_F(ErrorHandlingTest, BuildMessageWithNullParameters) {
    pb_byte_t buffer[500];
    size_t length = 0;
    
    // Test with null buffer
    int32_t amps = 12;
    int result1 = client->buildCarServerVehicleActionMessage(nullptr, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_EQ(result1, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null buffer should return INVALID_PARAMS";
    
    // Test with null length pointer
    int result2 = client->buildCarServerVehicleActionMessage(buffer, nullptr, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_EQ(result2, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null length pointer should return INVALID_PARAMS";
    
    // Test with both null
    int result3 = client->buildCarServerVehicleActionMessage(nullptr, nullptr, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_EQ(result3, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Both null should return INVALID_PARAMS";
}

TEST_F(ErrorHandlingTest, ParseMessageWithNullParameters) {
    UniversalMessage_RoutableMessage message;
    pb_byte_t buffer[100];
    
    // Test parseUniversalMessage with null buffer
    int result1 = client->parseUniversalMessage(nullptr, 10, &message);
    EXPECT_EQ(result1, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null input buffer should return INVALID_PARAMS";
    
    // Test parseUniversalMessage with null output
    int result2 = client->parseUniversalMessage(buffer, sizeof(buffer), nullptr);
    EXPECT_EQ(result2, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null output should return INVALID_PARAMS";
    
    // Test parseUniversalMessage with zero length
    int result3 = client->parseUniversalMessage(buffer, 0, &message);
    EXPECT_EQ(result3, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Zero length should return INVALID_PARAMS";
}

TEST_F(ErrorHandlingTest, ParseSessionInfoWithNullParameters) {
    UniversalMessage_RoutableMessage_session_info_t session_info;
    Signatures_SessionInfo output;
    
    // Initialize session_info with some data
    session_info.size = 10;
    memset(session_info.bytes, 0, 10);
    
    // Test parsePayloadSessionInfo with null input
    int result1 = client->parsePayloadSessionInfo(nullptr, &output);
    EXPECT_EQ(result1, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null input should return INVALID_PARAMS";
    
    // Test parsePayloadSessionInfo with null output
    int result2 = client->parsePayloadSessionInfo(&session_info, nullptr);
    EXPECT_EQ(result2, TeslaBLE::TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "Null output should return INVALID_PARAMS";
}

TEST_F(ErrorHandlingTest, PrivateKeyOperationsWithoutKey) {
    pb_byte_t buffer[300];
    size_t length = 0;
    
    // Try to get private key without having one loaded
    int result = client->getPrivateKey(buffer, sizeof(buffer), &length);
    EXPECT_NE(result, 0) << "Getting private key without loading one should fail";
}

TEST_F(ErrorHandlingTest, EdgeCaseFunctionCalls) {
    pb_byte_t buffer[500];
    size_t length = 0;
    
    // Test various boundary conditions
    pb_byte_t small_buffer[1];
    size_t small_length = 0;
    int32_t amps = 12;
    int result2 = client->buildCarServerVehicleActionMessage(small_buffer, &small_length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_NE(result2, 0) << "Building message with insufficient buffer should fail";
    
    // Test with boundary charge amounts
    int32_t zero_amps = 0;
    int result3 = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &zero_amps);
    EXPECT_NE(result3, 0) << "Building message with 0 amps should fail";
    
    int32_t high_percent = 101;
    int result4 = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_chargingSetLimitAction_tag, &high_percent);
    EXPECT_NE(result4, 0) << "Building message with >100% limit should fail";
    
    // Test buildUniversalMessageWithPayload without valid payload
    pb_byte_t output_buffer[300];
    size_t output_length = 0;
    pb_byte_t empty_payload[1] = {0};
    int result5 = client->buildUniversalMessageWithPayload(empty_payload, 0, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, output_buffer, &output_length);
    EXPECT_NE(result5, 0) << "Building universal message with empty payload should fail";
}
