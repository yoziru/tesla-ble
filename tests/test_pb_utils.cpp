#include <gtest/gtest.h>
#include <tb_utils.h>
#include <car_server.pb.h>
#include <vcsec.pb.h>
#include <cstring>

class PbUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup any required test data
    }

    void TearDown() override {
        // Cleanup
    }
};

TEST_F(PbUtilsTest, EncodeValidMessage) {
    // Create a simple vehicle action message
    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingSetLimitAction_tag;
    vehicle_action.vehicle_action_msg.chargingSetLimitAction.percent = 80;

    pb_byte_t output_buffer[500];
    size_t output_length = 0;

    int result = TeslaBLE::pb_encode_fields(
        output_buffer, 
        &output_length, 
        CarServer_VehicleAction_fields, 
        &vehicle_action
    );

    EXPECT_EQ(result, 0) << "Encoding valid message should succeed";
    EXPECT_GT(output_length, 0) << "Encoded message should have non-zero length";
    EXPECT_LE(output_length, sizeof(output_buffer)) << "Encoded message should fit in buffer";
}

TEST_F(PbUtilsTest, EncodeEmptyMessage) {
    // Create an empty/default message
    CarServer_VehicleAction empty_action = CarServer_VehicleAction_init_default;
    
    pb_byte_t output_buffer[500];
    size_t output_length = 0;

    int result = TeslaBLE::pb_encode_fields(
        output_buffer, 
        &output_length, 
        CarServer_VehicleAction_fields, 
        &empty_action
    );

    // This should fail because an empty message has no data to encode
    EXPECT_NE(result, 0) << "Encoding empty message should fail";
}

TEST_F(PbUtilsTest, EncodeChargingAmpsMessage) {
    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingSetLimitAction_tag;
    vehicle_action.vehicle_action_msg.chargingSetLimitAction.percent = 95;

    pb_byte_t output_buffer[500];
    size_t output_length = 0;

    int result = TeslaBLE::pb_encode_fields(
        output_buffer, 
        &output_length, 
        CarServer_VehicleAction_fields, 
        &vehicle_action
    );

    EXPECT_EQ(result, 0) << "Encoding charging limit message should succeed";
    EXPECT_GT(output_length, 0) << "Encoded charging limit message should have non-zero length";
}

TEST_F(PbUtilsTest, EncodeVCSECMessage) {
    VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
    unsigned_message.sub_message.RKEAction = VCSEC_RKEAction_E_RKE_ACTION_UNLOCK;

    pb_byte_t output_buffer[500];
    size_t output_length = 0;

    int result = TeslaBLE::pb_encode_fields(
        output_buffer, 
        &output_length, 
        VCSEC_UnsignedMessage_fields, 
        &unsigned_message
    );

    EXPECT_EQ(result, 0) << "Encoding VCSEC message should succeed";
    EXPECT_GT(output_length, 0) << "Encoded VCSEC message should have non-zero length";
}

TEST_F(PbUtilsTest, EncodeMultipleMessageTypes) {
    // Test encoding different types to ensure the utility function works broadly
    
    // Test 1: HVAC Action
    CarServer_VehicleAction hvac_action = CarServer_VehicleAction_init_default;
    hvac_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacAutoAction_tag;
    hvac_action.vehicle_action_msg.hvacAutoAction.power_on = true;

    pb_byte_t hvac_buffer[500];
    size_t hvac_length = 0;

    int hvac_result = TeslaBLE::pb_encode_fields(
        hvac_buffer, 
        &hvac_length, 
        CarServer_VehicleAction_fields, 
        &hvac_action
    );

    EXPECT_EQ(hvac_result, 0) << "Encoding HVAC action should succeed";
    EXPECT_GT(hvac_length, 0) << "HVAC action should have non-zero length";

    // Test 2: RKE Action
    VCSEC_UnsignedMessage rke_message = VCSEC_UnsignedMessage_init_default;
    rke_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
    rke_message.sub_message.RKEAction = VCSEC_RKEAction_E_RKE_ACTION_LOCK;

    pb_byte_t rke_buffer[500];
    size_t rke_length = 0;

    int rke_result = TeslaBLE::pb_encode_fields(
        rke_buffer, 
        &rke_length, 
        VCSEC_UnsignedMessage_fields, 
        &rke_message
    );

    EXPECT_EQ(rke_result, 0) << "Encoding RKE action should succeed";
    EXPECT_GT(rke_length, 0) << "RKE action should have non-zero length";

    // Results should be different for different message types
    EXPECT_NE(hvac_length, rke_length) << "Different message types should have different lengths";
}

TEST_F(PbUtilsTest, EncodeWithExactBufferSize) {
    // Create a message and find its exact size
    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingSetLimitAction_tag;
    vehicle_action.vehicle_action_msg.chargingSetLimitAction.percent = 80;

    // First pass: determine size
    pb_byte_t temp_buffer[500];
    size_t required_length = 0;

    int size_result = TeslaBLE::pb_encode_fields(
        temp_buffer, 
        &required_length, 
        CarServer_VehicleAction_fields, 
        &vehicle_action
    );

    ASSERT_EQ(size_result, 0) << "Initial encoding should succeed";
    ASSERT_GT(required_length, 0) << "Should have determined a positive length";

    // Second pass: use exact buffer size
    std::vector<pb_byte_t> exact_buffer(required_length);
    size_t exact_length = 0;

    int exact_result = TeslaBLE::pb_encode_fields(
        exact_buffer.data(), 
        &exact_length, 
        CarServer_VehicleAction_fields, 
        &vehicle_action
    );

    EXPECT_EQ(exact_result, 0) << "Encoding with exact buffer size should succeed";
    EXPECT_EQ(exact_length, required_length) << "Length should match exactly";
}
