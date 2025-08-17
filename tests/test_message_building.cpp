#include <gtest/gtest.h>
#include <client.h>
#include <cstring>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include <signatures.pb.h>
#include <car_server.pb.h>

// Mock data
static const char *MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

// Mock received message from VCSEC (same as in session management tests)
static pb_byte_t MOCK_VCSEC_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x2f, 0xdd, 0xc1, 0x45, 0xca, 0xcc, 0xca, 0x43, 0x05, 0x66, 0x37, 0x0d, 
    0xf1, 0x49, 0x85, 0x5d, 0x3a, 0x02, 0x08, 0x02, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 
    0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 
    0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 
    0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 
    0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 
    0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 
    0xe6, 0x25, 0x85, 0x4a, 0x00, 0x00, 0x30, 0x06, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20, 0x5a, 0x0d, 
    0x3c, 0x7c, 0xb0, 0x2c, 0x04, 0xd9, 0x12, 0xa3, 0x58, 0x8b, 0xc2, 0xa6, 0xfd, 0x8c, 0x00, 0xf2, 
    0x44, 0x09, 0x1b, 0xdd, 0x9d, 0xfe, 0x46, 0xfc, 0xdc, 0x47, 0x06, 0x41, 0x5b, 0x26, 0x92, 0x03, 
    0x10, 0x3c, 0xcc, 0xe3, 0xd5, 0x1a, 0x6f, 0x3c, 0x2a, 0xee, 0xa8, 0x91, 0x36, 0x44, 0xa7, 0x05, 0x84
};

// Mock received message from INFOTAINMENT (same as in session management tests)
static pb_byte_t MOCK_INFOTAINMENT_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 
    0xc9, 0x28, 0xb5, 0xe7, 0x3a, 0x02, 0x08, 0x03, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 
    0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 
    0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 
    0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 
    0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 
    0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 
    0xe6, 0x25, 0x5f, 0x0a, 0x00, 0x00, 0x30, 0x07, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20, 0x8e, 0x8d, 
    0xcd, 0x16, 0x4e, 0xf3, 0x61, 0xfd, 0x12, 0x3c, 0x46, 0xc2, 0xb2, 0xbd, 0xfd, 0x1f, 0xc9, 0x30, 
    0x56, 0xf4, 0xef, 0x32, 0xc9, 0x31, 0x1a, 0x27, 0x5d, 0xb9, 0x08, 0xd4, 0xd2, 0x3f, 0x92, 0x03, 
    0x10, 0x0a, 0x40, 0x4e, 0xc0, 0xfc, 0x9a, 0xa8, 0x63, 0xae, 0xc3, 0xe5, 0x01, 0x96, 0xfb, 0xf3, 0x0b
};

class MessageBuildingTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<TeslaBLE::Client>();
        client->setVIN(MOCK_VIN);
        
        // Load private key for message building
        int status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
        ASSERT_EQ(status, 0) << "Failed to load private key for testing";
        
        // Set connection ID
        pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26, 
                                      0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
        client->setConnectionID(connection_id);
        
        // Initialize VCSEC session for message building that requires encryption
        initializeVCSECSession();
        
        // Initialize Infotainment session for car server messages
        initializeInfotainmentSession();
    }
    
    void initializeVCSECSession() {
        // Parse the VCSEC message to get session info
        UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
        int parse_result = client->parseUniversalMessage(
            MOCK_VCSEC_MESSAGE, 
            sizeof(MOCK_VCSEC_MESSAGE), 
            &received_message
        );
        ASSERT_EQ(parse_result, 0) << "Failed to parse VCSEC message";
        
        // Parse session info
        Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
        int session_parse_result = client->parsePayloadSessionInfo(
            &received_message.payload.session_info, 
            &session_info
        );
        ASSERT_EQ(session_parse_result, 0) << "Failed to parse session info";
        
        // Get peer and update session
        auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
        ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";
        
        int update_result = vcsec_peer->updateSession(&session_info);
        ASSERT_EQ(update_result, 0) << "Updating VCSEC session should succeed";
        ASSERT_TRUE(vcsec_peer->isInitialized()) << "VCSEC peer should be initialized after update";
    }
    
    void initializeInfotainmentSession() {
        // Parse the Infotainment message to get session info
        UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
        int parse_result = client->parseUniversalMessage(
            MOCK_INFOTAINMENT_MESSAGE, 
            sizeof(MOCK_INFOTAINMENT_MESSAGE), 
            &received_message
        );
        ASSERT_EQ(parse_result, 0) << "Failed to parse Infotainment message";
        
        // Parse session info
        Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
        int session_parse_result = client->parsePayloadSessionInfo(
            &received_message.payload.session_info, 
            &session_info
        );
        ASSERT_EQ(session_parse_result, 0) << "Failed to parse session info";
        
        // Get peer and update session
        auto infotainment_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
        ASSERT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";
        
        int update_result = infotainment_peer->updateSession(&session_info);
        ASSERT_EQ(update_result, 0) << "Updating Infotainment session should succeed";
        ASSERT_TRUE(infotainment_peer->isInitialized()) << "Infotainment peer should be initialized after update";
    }

    void TearDown() override {
        client.reset();
    }

    std::unique_ptr<TeslaBLE::Client> client;
};

TEST_F(MessageBuildingTest, BuildWhiteListMessage) {
    unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
    size_t whitelist_message_length;
    
    int result = client->buildWhiteListMessage(
        Keys_Role_ROLE_CHARGING_MANAGER, 
        VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY, 
        whitelist_message_buffer, 
        &whitelist_message_length
    );
    
    EXPECT_EQ(result, 0) << "Building whitelist message should succeed";
    EXPECT_GT(whitelist_message_length, 0) << "Whitelist message should have non-zero length";
    EXPECT_LE(whitelist_message_length, sizeof(whitelist_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECActionMessage) {
    unsigned char action_message_buffer[UniversalMessage_RoutableMessage_size];
    size_t action_message_buffer_length = 0;
    
    int result = client->buildVCSECActionMessage(
        VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, 
        action_message_buffer, 
        &action_message_buffer_length
    );
    
    EXPECT_EQ(result, 0) << "Building VCSEC action message should succeed";
    EXPECT_GT(action_message_buffer_length, 0) << "Action message should have non-zero length";
    EXPECT_LE(action_message_buffer_length, sizeof(action_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECInformationRequestMessage) {
    pb_byte_t info_request_buffer[UniversalMessage_RoutableMessage_size];
    size_t info_request_length = 0;
    
    int result = client->buildVCSECInformationRequestMessage(
        VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, 
        info_request_buffer, 
        &info_request_length
    );
    
    EXPECT_EQ(result, 0) << "Building VCSEC information request should succeed";
    EXPECT_GT(info_request_length, 0) << "Information request should have non-zero length";
    EXPECT_LE(info_request_length, sizeof(info_request_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildChargingAmpsMessage) {
    pb_byte_t charging_amps_buffer[UniversalMessage_RoutableMessage_size];
    size_t charging_amps_length = 0;  // Initialize to avoid garbage values
    
    int32_t amps = 12;
    int result = client->buildCarServerVehicleActionMessage(charging_amps_buffer, &charging_amps_length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    
    EXPECT_EQ(result, 0) << "Building charging amps message should succeed";
    EXPECT_GT(charging_amps_length, 0) << "Charging amps message should have non-zero length";
    EXPECT_LE(charging_amps_length, sizeof(charging_amps_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildChargingSetLimitMessage) {
    pb_byte_t charging_limit_buffer[UniversalMessage_RoutableMessage_size];
    size_t charging_limit_length = 0;  // Initialize to avoid garbage values
    
    int32_t percent = 95;
    int result = client->buildCarServerVehicleActionMessage(charging_limit_buffer, &charging_limit_length, CarServer_VehicleAction_chargingSetLimitAction_tag, &percent);
    
    EXPECT_EQ(result, 0) << "Building charging limit message should succeed";
    EXPECT_GT(charging_limit_length, 0) << "Charging limit message should have non-zero length";
    EXPECT_LE(charging_limit_length, sizeof(charging_limit_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildHVACMessage) {
    pb_byte_t hvac_buffer[UniversalMessage_RoutableMessage_size];
    size_t hvac_length = 0;  // Initialize to avoid garbage values
    
    // Test turning HVAC on
    bool hvac_on = true;
    int result_on = client->buildCarServerVehicleActionMessage(hvac_buffer, &hvac_length, CarServer_VehicleAction_hvacAutoAction_tag, &hvac_on);
    EXPECT_EQ(result_on, 0) << "Building HVAC ON message should succeed";
    EXPECT_GT(hvac_length, 0) << "HVAC ON message should have non-zero length";
    
    // Test turning HVAC off  
    hvac_length = 0;  // Reset for second test
    bool hvac_off = false;
    int result_off = client->buildCarServerVehicleActionMessage(hvac_buffer, &hvac_length, CarServer_VehicleAction_hvacAutoAction_tag, &hvac_off);
    EXPECT_EQ(result_off, 0) << "Building HVAC OFF message should succeed";
    EXPECT_GT(hvac_length, 0) << "HVAC OFF message should have non-zero length";
}

TEST_F(MessageBuildingTest, BuildMessagesWithInvalidParameters) {
    unsigned char buffer[UniversalMessage_RoutableMessage_size];
    size_t length = 0;  // Initialize to avoid garbage values
    
    // Test with null buffer
    int32_t amps = 12;
    int result1 = client->buildCarServerVehicleActionMessage(nullptr, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_NE(result1, 0) << "Building message with null buffer should fail";
    
    // Test with null length pointer
    int result2 = client->buildCarServerVehicleActionMessage(buffer, nullptr, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
    EXPECT_NE(result2, 0) << "Building message with null length pointer should fail";
}

TEST_F(MessageBuildingTest, BuildCarServerGetVehicleDataMessage) {
    pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
    size_t length = 0;
    
    // Test with charge state data
    int result = client->buildCarServerGetVehicleDataMessage(buffer, &length, CarServer_GetVehicleData_getChargeState_tag);
    EXPECT_EQ(result, 0) << "Building get charge state message should succeed";
    EXPECT_GT(length, 0) << "Get charge state message should have non-zero length";
    EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
    
    // Test with climate state data
    length = 0;
    result = client->buildCarServerGetVehicleDataMessage(buffer, &length, CarServer_GetVehicleData_getClimateState_tag);
    EXPECT_EQ(result, 0) << "Building get climate state message should succeed";
    EXPECT_GT(length, 0) << "Get climate state message should have non-zero length";
    
    // Test with drive state data
    length = 0;
    result = client->buildCarServerGetVehicleDataMessage(buffer, &length, CarServer_GetVehicleData_getDriveState_tag);
    EXPECT_EQ(result, 0) << "Building get drive state message should succeed";
    EXPECT_GT(length, 0) << "Get drive state message should have non-zero length";
    
    // Test with location state data
    length = 0;
    result = client->buildCarServerGetVehicleDataMessage(buffer, &length, CarServer_GetVehicleData_getLocationState_tag);
    EXPECT_EQ(result, 0) << "Building get location state message should succeed";
    EXPECT_GT(length, 0) << "Get location state message should have non-zero length";
}

TEST_F(MessageBuildingTest, BuildCarServerGetVehicleDataMessageAllTypes) {
    pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
    size_t length = 0;
    
    // Use nanopb's auto-generated FIELDLIST macro to dynamically discover all vehicle data types
    // This leverages the existing CarServer_GetVehicleData_FIELDLIST macro from car_server.pb.h
    // which is automatically generated from the proto definition
    struct VehicleDataTag {
        const char* name;
        int32_t tag;
    };
    
    std::vector<VehicleDataTag> all_vehicle_data_tags;
    
    // Extract field names and tag numbers from the nanopb FIELDLIST macro
    // This macro is automatically generated and will include any new fields added to the proto
#define EXTRACT_FIELD_INFO(a, type, label, datatype, name, tag_num) \
    all_vehicle_data_tags.push_back({#name, CarServer_GetVehicleData_##name##_tag});
    
    CarServer_GetVehicleData_FIELDLIST(EXTRACT_FIELD_INFO, unused)
    
#undef EXTRACT_FIELD_INFO
    
    // Verify tags are unique (no duplicates)
    std::set<int32_t> unique_tags;
    for (const auto& tag_info : all_vehicle_data_tags) {
        ASSERT_TRUE(unique_tags.insert(tag_info.tag).second) 
            << "Duplicate tag value " << tag_info.tag << " found for " << tag_info.name;
    }
    
    // Test each vehicle data type discovered from the proto
    for (const auto& tag_info : all_vehicle_data_tags) {
        length = 0;  // Reset for each test
        int result = client->buildCarServerGetVehicleDataMessage(buffer, &length, tag_info.tag);
        EXPECT_EQ(result, 0) << "Building get vehicle data message with type " << tag_info.name << " (" << tag_info.tag << ") should succeed";
        EXPECT_GT(length, 0) << "Get vehicle data message should have non-zero length for type " << tag_info.name << " (" << tag_info.tag << ")";
        EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer for type " << tag_info.name << " (" << tag_info.tag << ")";
    }
    
    // This test will automatically include any new vehicle data types added to the proto
    // without requiring manual updates to the test code
    std::cout << "Tested " << all_vehicle_data_tags.size() << " vehicle data types discovered from proto definition:" << std::endl;
    for (const auto& tag_info : all_vehicle_data_tags) {
        std::cout << "  " << tag_info.name << " = " << tag_info.tag << std::endl;
    }
}

TEST_F(MessageBuildingTest, BuildCarServerGetVehicleDataMessageInvalidType) {
    pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
    size_t length = 0;
    
    // Test with invalid vehicle data type
    int result = client->buildCarServerGetVehicleDataMessage(buffer, &length, 999);
    EXPECT_NE(result, 0) << "Building get vehicle data message with invalid type should fail";
}

TEST_F(MessageBuildingTest, BuildMessagesWithValidParameterRanges) {
    pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
    size_t length = 0;  // Initialize to avoid garbage values
    
    // Test charging amps with various valid values
    std::vector<int> valid_amps = {1, 5, 10, 15, 20, 32, 48};
    for (int amps_val : valid_amps) {
        length = 0;  // Reset for each test
        int32_t amps = amps_val;
        int result = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
        EXPECT_EQ(result, 0) << "Building charging amps message with " << amps << " amps should succeed";
    }
    
    // Test charging limit with various valid values
    std::vector<int> valid_limits = {50, 70, 80, 90, 95, 100};
    for (int limit_val : valid_limits) {
        length = 0;  // Reset for each test
        int32_t percent = limit_val;
        int result = client->buildCarServerVehicleActionMessage(buffer, &length, CarServer_VehicleAction_chargingSetLimitAction_tag, &percent);
        EXPECT_EQ(result, 0) << "Building charging limit message with " << percent << "% should succeed";
    }
}
