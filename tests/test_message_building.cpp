#include <gtest/gtest.h>
#include <client.h>
#include <cstring>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include <signatures.pb.h>
#include <car_server.pb.h>
#include "test_constants.h"

using namespace TeslaBLE;

// Mock data
static const char *MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] =
    "-----BEGIN EC PRIVATE "
    "KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/"
    "lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+"
    "fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

// Mock received message from VCSEC (same as in session management tests)
static pb_byte_t MOCK_VCSEC_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x2f, 0xdd, 0xc1, 0x45, 0xca, 0xcc, 0xca, 0x43, 0x05, 0x66, 0x37, 0x0d, 0xf1, 0x49,
    0x85, 0x5d, 0x3a, 0x02, 0x08, 0x02, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38,
    0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48,
    0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf,
    0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13,
    0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82,
    0xed, 0x22, 0x4a, 0xdd, 0xe6, 0x25, 0x85, 0x4a, 0x00, 0x00, 0x30, 0x06, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20,
    0x5a, 0x0d, 0x3c, 0x7c, 0xb0, 0x2c, 0x04, 0xd9, 0x12, 0xa3, 0x58, 0x8b, 0xc2, 0xa6, 0xfd, 0x8c, 0x00, 0xf2,
    0x44, 0x09, 0x1b, 0xdd, 0x9d, 0xfe, 0x46, 0xfc, 0xdc, 0x47, 0x06, 0x41, 0x5b, 0x26, 0x92, 0x03, 0x10, 0x3c,
    0xcc, 0xe3, 0xd5, 0x1a, 0x6f, 0x3c, 0x2a, 0xee, 0xa8, 0x91, 0x36, 0x44, 0xa7, 0x05, 0x84};

// Mock received message from INFOTAINMENT (same as in session management tests)
static pb_byte_t MOCK_INFOTAINMENT_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 0xc9, 0x28,
    0xb5, 0xe7, 0x3a, 0x02, 0x08, 0x03, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38,
    0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48,
    0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf,
    0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13,
    0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82,
    0xed, 0x22, 0x4a, 0xdd, 0xe6, 0x25, 0x5f, 0x0a, 0x00, 0x00, 0x30, 0x07, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20,
    0x8e, 0x8d, 0xcd, 0x16, 0x4e, 0xf3, 0x61, 0xfd, 0x12, 0x3c, 0x46, 0xc2, 0xb2, 0xbd, 0xfd, 0x1f, 0xc9, 0x30,
    0x56, 0xf4, 0xef, 0x32, 0xc9, 0x31, 0x1a, 0x27, 0x5d, 0xb9, 0x08, 0xd4, 0xd2, 0x3f, 0x92, 0x03, 0x10, 0x0a,
    0x40, 0x4e, 0xc0, 0xfc, 0x9a, 0xa8, 0x63, 0xae, 0xc3, 0xe5, 0x01, 0x96, 0xfb, 0xf3, 0x0b};

class MessageBuildingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client = std::make_unique<TeslaBLE::Client>();
    client->set_vin(MOCK_VIN);

    // Load private key for message building
    TeslaBLEStatus status =
        client->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                 strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    ASSERT_EQ(status, TeslaBLEStatus::OK) << "Failed to load private key for testing";

    // Set connection ID
    pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26,
                                   0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
    client->set_connection_id(connection_id);

    // Initialize VCSEC session for message building that requires encryption
    initializeVCSECSession();

    // Initialize Infotainment session for car server messages
    initializeInfotainmentSession();
  }

  void initializeVCSECSession() {
    // Parse the VCSEC message to get session info
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    auto parse_result =
        client->parse_universal_message(MOCK_VCSEC_MESSAGE, sizeof(MOCK_VCSEC_MESSAGE), &received_message);
    ASSERT_EQ(parse_result, TeslaBLEStatus::OK) << "Failed to parse VCSEC message";

    // Parse session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    auto session_parse_result =
        client->parse_payload_session_info(&received_message.payload.session_info, &session_info);
    ASSERT_EQ(session_parse_result, TeslaBLEStatus::OK) << "Failed to parse session info";

    // Get peer and update session
    auto vcsec_peer = client->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

    auto update_result = vcsec_peer->update_session(&session_info);
    ASSERT_EQ(update_result, TeslaBLEStatus::OK) << "Updating VCSEC session should succeed";
    ASSERT_TRUE(vcsec_peer->is_initialized()) << "VCSEC peer should be initialized after update";
  }

  void initializeInfotainmentSession() {
    // Parse the Infotainment message to get session info
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    auto parse_result = client->parse_universal_message(MOCK_INFOTAINMENT_MESSAGE, sizeof(MOCK_INFOTAINMENT_MESSAGE),
                                                        &received_message);
    ASSERT_EQ(parse_result, TeslaBLEStatus::OK) << "Failed to parse Infotainment message";

    // Parse session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    auto session_parse_result =
        client->parse_payload_session_info(&received_message.payload.session_info, &session_info);
    ASSERT_EQ(session_parse_result, TeslaBLEStatus::OK) << "Failed to parse session info";

    // Get peer and update session
    auto infotainment_peer = client->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    ASSERT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";

    auto update_result = infotainment_peer->update_session(&session_info);
    ASSERT_EQ(update_result, TeslaBLEStatus::OK) << "Updating Infotainment session should succeed";
    ASSERT_TRUE(infotainment_peer->is_initialized()) << "Infotainment peer should be initialized after update";
  }

  void TearDown() override { client.reset(); }

  std::unique_ptr<TeslaBLE::Client> client;
};

TEST_F(MessageBuildingTest, BuildWhiteListMessage) {
  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;

  auto result =
      client->build_white_list_message(Keys_Role_ROLE_CHARGING_MANAGER, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                       whitelist_message_buffer, &whitelist_message_length);

  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building whitelist message should succeed";
  EXPECT_GT(whitelist_message_length, 0) << "Whitelist message should have non-zero length";
  EXPECT_LE(whitelist_message_length, sizeof(whitelist_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECActionMessage) {
  unsigned char action_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t action_message_buffer_length = 0;

  auto result = client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, action_message_buffer,
                                                   &action_message_buffer_length);

  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building VCSEC action message should succeed";
  EXPECT_GT(action_message_buffer_length, 0) << "Action message should have non-zero length";
  EXPECT_LE(action_message_buffer_length, sizeof(action_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECInformationRequestMessage) {
  pb_byte_t info_request_buffer[UniversalMessage_RoutableMessage_size];
  size_t info_request_length = 0;

  auto result = client->build_vcsec_information_request_message(
      VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, info_request_buffer, &info_request_length);

  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building VCSEC information request should succeed";
  EXPECT_GT(info_request_length, 0) << "Information request should have non-zero length";
  EXPECT_LE(info_request_length, sizeof(info_request_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECClosureMessage) {
  unsigned char closure_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t closure_message_length = 0;

  VCSEC_ClosureMoveRequest closure_request = VCSEC_ClosureMoveRequest_init_default;
  closure_request.frontDriverDoor = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
  closure_request.rearTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;

  auto result = client->build_vcsec_closure_message(&closure_request, closure_message_buffer, &closure_message_length);

  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building closure message should succeed";
  EXPECT_GT(closure_message_length, 0) << "Closure message should have non-zero length";
  EXPECT_LE(closure_message_length, sizeof(closure_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECClosureMessageMultipleDoors) {
  unsigned char closure_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t closure_message_length = 0;

  VCSEC_ClosureMoveRequest closure_request = VCSEC_ClosureMoveRequest_init_default;
  closure_request.frontDriverDoor = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
  closure_request.rearDriverDoor = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;
  closure_request.rearTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;

  auto result = client->build_vcsec_closure_message(&closure_request, closure_message_buffer, &closure_message_length);

  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building closure message with multiple doors should succeed";
  EXPECT_GT(closure_message_length, 0) << "Closure message should have non-zero length";
  EXPECT_LE(closure_message_length, sizeof(closure_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildMessagesWithInvalidParameters) {
  unsigned char buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;  // Initialize to avoid garbage values

  // Test with null buffer
  int32_t amps = 12;
  auto result = client->build_car_server_vehicle_action_message(
      nullptr, &length, CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_NE(result, TeslaBLEStatus::OK) << "Building message with null buffer should fail";

  // Test with null length pointer
  result = client->build_car_server_vehicle_action_message(buffer, nullptr,
                                                           CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_NE(result, TeslaBLEStatus::OK) << "Building message with null length pointer should fail";
}

// Individual tests for each vehicle data type - automatically generated from protobuf definition
class VehicleDataTest : public MessageBuildingTest {
 protected:
  struct VehicleDataTag {
    std::string name;
    int32_t tag;
  };

  static std::vector<VehicleDataTag> getAllVehicleDataTags() {
    std::vector<VehicleDataTag> all_vehicle_data_tags;

    // Extract field names and tag numbers from the nanopb FIELDLIST macro
    // clang-format off
#define EXTRACT_FIELD_INFO(a, type, label, datatype, name, tag_num) \
  all_vehicle_data_tags.push_back({#name, CarServer_GetVehicleData_##name##_tag});

    CarServer_GetVehicleData_FIELDLIST(EXTRACT_FIELD_INFO, unused)
    // clang-format on

#undef EXTRACT_FIELD_INFO

        return all_vehicle_data_tags;
  }
};

TEST_F(VehicleDataTest, VehicleDataTagsAreUnique) {
  auto all_tags = getAllVehicleDataTags();

  // Verify tags are unique (no duplicates)
  std::set<int32_t> unique_tags;
  for (const auto &tag_info : all_tags) {
    ASSERT_TRUE(unique_tags.insert(tag_info.tag).second)
        << "Duplicate tag value " << tag_info.tag << " found for " << tag_info.name;
  }

  EXPECT_GT(all_tags.size(), 0) << "Should discover at least one vehicle data type";
}

TEST_F(VehicleDataTest, VehicleDataCoverageReport) {
  auto all_tags = getAllVehicleDataTags();

  std::cout << "\n=== VEHICLE DATA COVERAGE REPORT ===" << std::endl;
  std::cout << "Total vehicle data types discovered: " << all_tags.size() << std::endl;
  std::cout << "All types tested individually below:" << std::endl;

  for (const auto &tag_info : all_tags) {
    std::cout << "  " << tag_info.name << " = " << tag_info.tag << std::endl;
  }
  std::cout << "======================================\n" << std::endl;
}

// Generate individual test for each vehicle data type
#define GENERATE_VEHICLE_DATA_TEST(a, type, label, datatype, name, tag_num) \
  TEST_F(VehicleDataTest, VehicleData_##name) { \
    pb_byte_t buffer[UniversalMessage_RoutableMessage_size]; \
    size_t length = 0; \
\
    auto result = \
        client->build_car_server_get_vehicle_data_message(buffer, &length, CarServer_GetVehicleData_##name##_tag); \
    EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building get vehicle data message for " #name " should succeed"; \
    EXPECT_GT(length, 0) << "Get vehicle data message should have non-zero length for " #name; \
    EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer for " #name; \
  }

// Auto-generate individual tests for all vehicle data types
CarServer_GetVehicleData_FIELDLIST(GENERATE_VEHICLE_DATA_TEST, unused)
#undef GENERATE_VEHICLE_DATA_TEST

    TEST_F(MessageBuildingTest, BuildCarServerGetVehicleDataMessageInvalidType) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  // Test with invalid vehicle data type
  auto result = client->build_car_server_get_vehicle_data_message(buffer, &length, 999);
  EXPECT_NE(result, TeslaBLEStatus::OK) << "Building get vehicle data message with invalid type should fail";
}

// Helper function to get all vehicle action tags - shared across multiple tests
std::vector<std::pair<std::string, int32_t>> GetAllVehicleActionTags() {
  std::vector<std::pair<std::string, int32_t>> all_vehicle_action_tags;

  // Extract field names and tag numbers from the nanopb FIELDLIST macro
#define EXTRACT_VEHICLE_ACTION_INFO(a, type, label, datatype, name_tuple, tag_num) \
  { \
    const char *action_name = #name_tuple; \
    /* Extract the middle part from (vehicle_action_msg,actionName,vehicle_action_msg.actionName) */ \
    std::string full_name(action_name); \
    size_t first_comma = full_name.find(','); \
    size_t second_comma = full_name.find(',', first_comma + 1); \
    if (first_comma != std::string::npos && second_comma != std::string::npos) { \
      std::string action_name_clean = full_name.substr(first_comma + 1, second_comma - first_comma - 1); \
      all_vehicle_action_tags.push_back({action_name_clean, tag_num}); \
    } \
  }

  CarServer_VehicleAction_FIELDLIST(EXTRACT_VEHICLE_ACTION_INFO, unused)

#undef EXTRACT_VEHICLE_ACTION_INFO

      return all_vehicle_action_tags;
}

TEST_F(MessageBuildingTest, VehicleActionTagsAreUnique) {
  auto all_tags = GetAllVehicleActionTags();

  // Verify tags are unique (no duplicates)
  std::set<int32_t> unique_tags;
  for (const auto &tag_pair : all_tags) {
    ASSERT_TRUE(unique_tags.insert(tag_pair.second).second)
        << "Duplicate tag value " << tag_pair.second << " found for " << tag_pair.first;
  }

  // Ensure we discovered a reasonable number of actions
  EXPECT_GE(all_tags.size(), 50) << "Should discover at least 50 vehicle actions from protobuf";

  std::cout << "Discovered " << all_tags.size() << " unique vehicle action types from protobuf" << std::endl;
}

// Test simple vehicle actions that don't require parameters
class VehicleActionSimpleTest : public MessageBuildingTest,
                                public ::testing::WithParamInterface<std::pair<std::string, int32_t>> {};

TEST_P(VehicleActionSimpleTest, BuildSimpleVehicleActionMessage) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto [action_name, tag] = GetParam();

  auto result = client->build_car_server_vehicle_action_message(buffer, &length, tag, nullptr);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building simple vehicle action message " << action_name << " (" << tag
                                        << ") should succeed";
  EXPECT_GT(length, 0) << "Vehicle action message should have non-zero length for " << action_name;
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer for " << action_name;
}

INSTANTIATE_TEST_SUITE_P(
    SimpleActions, VehicleActionSimpleTest,
    ::testing::Values(
        std::make_pair("vehicleControlFlashLightsAction", CarServer_VehicleAction_vehicleControlFlashLightsAction_tag),
        std::make_pair("vehicleControlHonkHornAction", CarServer_VehicleAction_vehicleControlHonkHornAction_tag),
        std::make_pair("chargePortDoorOpen", CarServer_VehicleAction_chargePortDoorOpen_tag),
        std::make_pair("chargePortDoorClose", CarServer_VehicleAction_chargePortDoorClose_tag),
        std::make_pair("mediaPlayAction", CarServer_VehicleAction_mediaPlayAction_tag),
        std::make_pair("mediaNextFavorite", CarServer_VehicleAction_mediaNextFavorite_tag),
        std::make_pair("mediaPreviousFavorite", CarServer_VehicleAction_mediaPreviousFavorite_tag),
        std::make_pair("mediaNextTrack", CarServer_VehicleAction_mediaNextTrack_tag),
        std::make_pair("mediaPreviousTrack", CarServer_VehicleAction_mediaPreviousTrack_tag),
        std::make_pair("vehicleControlCancelSoftwareUpdateAction",
                       CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag),
        std::make_pair("vehicleControlResetValetPinAction",
                       CarServer_VehicleAction_vehicleControlResetValetPinAction_tag),
        std::make_pair("vehicleControlResetPinToDriveAction",
                       CarServer_VehicleAction_vehicleControlResetPinToDriveAction_tag),
        std::make_pair("drivingClearSpeedLimitPinAdminAction",
                       CarServer_VehicleAction_drivingClearSpeedLimitPinAdminAction_tag),
        std::make_pair("vehicleControlResetPinToDriveAdminAction",
                       CarServer_VehicleAction_vehicleControlResetPinToDriveAdminAction_tag)),
    [](const ::testing::TestParamInfo<VehicleActionSimpleTest::ParamType> &info) { return info.param.first; });

// Test boolean vehicle actions
class VehicleActionBooleanTest : public MessageBuildingTest,
                                 public ::testing::WithParamInterface<std::tuple<std::string, int32_t, bool>> {};

TEST_P(VehicleActionBooleanTest, BuildBooleanVehicleActionMessage) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto [action_name, tag, test_value] = GetParam();

  auto result = client->build_car_server_vehicle_action_message(buffer, &length, tag, &test_value);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building boolean vehicle action message " << action_name << " (" << tag
                                        << ") with value " << test_value << " should succeed";
  EXPECT_GT(length, 0) << "Vehicle action message should have non-zero length for " << action_name;
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer for " << action_name;
}

INSTANTIATE_TEST_SUITE_P(
    BooleanActions, VehicleActionBooleanTest,
    ::testing::Values(std::make_tuple("vehicleControlSetSentryModeAction_On",
                                      CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, true),
                      std::make_tuple("vehicleControlSetSentryModeAction_Off",
                                      CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, false),
                      std::make_tuple("hvacAutoAction_On", CarServer_VehicleAction_hvacAutoAction_tag, true),
                      std::make_tuple("hvacAutoAction_Off", CarServer_VehicleAction_hvacAutoAction_tag, false),
                      std::make_tuple("hvacSteeringWheelHeaterAction_On",
                                      CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag, true),
                      std::make_tuple("hvacSteeringWheelHeaterAction_Off",
                                      CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag, false)),
    [](const ::testing::TestParamInfo<VehicleActionBooleanTest::ParamType> &info) { return std::get<0>(info.param); });

// Test numeric vehicle actions
class VehicleActionNumericTest : public MessageBuildingTest,
                                 public ::testing::WithParamInterface<std::tuple<std::string, int32_t, int32_t>> {};

TEST_P(VehicleActionNumericTest, BuildNumericVehicleActionMessage) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto [action_name, tag, test_value] = GetParam();

  auto result = client->build_car_server_vehicle_action_message(buffer, &length, tag, &test_value);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building numeric vehicle action message " << action_name << " (" << tag
                                        << ") with value " << test_value << " should succeed";
  EXPECT_GT(length, 0) << "Vehicle action message should have non-zero length for " << action_name;
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer for " << action_name;
}

INSTANTIATE_TEST_SUITE_P(
    NumericActions, VehicleActionNumericTest,
    ::testing::Values(
        std::make_tuple("setChargingAmpsAction_16A", CarServer_VehicleAction_setChargingAmpsAction_tag, 16),
        std::make_tuple("setChargingAmpsAction_32A", CarServer_VehicleAction_setChargingAmpsAction_tag, 32),
        std::make_tuple("chargingSetLimitAction_80pct", CarServer_VehicleAction_chargingSetLimitAction_tag, 80),
        std::make_tuple("chargingSetLimitAction_90pct", CarServer_VehicleAction_chargingSetLimitAction_tag, 90),
        std::make_tuple("ping_12345", CarServer_VehicleAction_ping_tag, 12345),
        std::make_tuple("ping_99999", CarServer_VehicleAction_ping_tag, 99999)),
    [](const ::testing::TestParamInfo<VehicleActionNumericTest::ParamType> &info) { return std::get<0>(info.param); });

TEST_F(MessageBuildingTest, VehicleActionCoverageReport) {
  auto all_tags = GetAllVehicleActionTags();

  // Count different types of actions we're testing
  int simple_actions = 14;  // From INSTANTIATE_TEST_SUITE_P SimpleActions
  int boolean_actions = 6;  // From INSTANTIATE_TEST_SUITE_P BooleanActions (3 actions * 2 values each)
  int numeric_actions = 6;  // From INSTANTIATE_TEST_SUITE_P NumericActions
  int tested_actions = simple_actions + boolean_actions + numeric_actions;
  int total_actions = all_tags.size();
  int skipped_actions = total_actions - tested_actions - 1;  // -1 for getVehicleData

  std::cout << "=== Vehicle Action Test Coverage Report ===" << std::endl;
  std::cout << "Total actions discovered: " << total_actions << std::endl;
  std::cout << "Simple actions tested: " << simple_actions << std::endl;
  std::cout << "Boolean actions tested: " << boolean_actions << " (3 actions × 2 values)" << std::endl;
  std::cout << "Numeric actions tested: " << numeric_actions << " (3 actions × 2 values)" << std::endl;
  std::cout << "Total test cases: " << tested_actions << std::endl;
  std::cout << "Complex actions (require structs): " << skipped_actions << std::endl;
  std::cout << "Coverage: " << (tested_actions * 100 / total_actions) << "%" << std::endl;

  // Ensure we have reasonable coverage
  EXPECT_GE(tested_actions, 20) << "Should have at least 20 individual test cases for vehicle actions";

  std::cout << "\nAll discovered vehicle action types:" << std::endl;
  for (const auto &tag_pair : all_tags) {
    std::cout << "  " << tag_pair.first << " = " << tag_pair.second << std::endl;
  }
}

TEST_F(MessageBuildingTest, SetCabinOverheatProtection_On) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto result = client->set_cabin_overheat_protection(buffer, &length, true, false);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Setting cabin overheat protection ON should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, SetCabinOverheatProtection_Off) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto result = client->set_cabin_overheat_protection(buffer, &length, false, false);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Setting cabin overheat protection OFF should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, SetCabinOverheatProtection_FanOnly) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto result = client->set_cabin_overheat_protection(buffer, &length, true, true);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Setting cabin overheat protection fan_only should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, ScheduleSoftwareUpdate) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  int32_t offset_sec = 3600;  // 1 hour from now
  auto result = client->schedule_software_update(buffer, &length, offset_sec);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Scheduling software update should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, ScheduleSoftwareUpdate_Delay) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  int32_t offset_sec = 86400;  // 24 hours from now
  auto result = client->schedule_software_update(buffer, &length, offset_sec);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Scheduling software update with 24h delay should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, CancelSoftwareUpdate) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto result = client->cancel_software_update(buffer, &length);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Canceling software update should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildScheduleSoftwareUpdateViaBuilder) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  int32_t offset_sec = 7200;  // 2 hours
  auto result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag, &offset_sec);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building schedule software update via builder should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, BuildSetCabinOverheatProtectionViaBuilder) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  CarServer_SetCabinOverheatProtectionAction cop_action = CarServer_SetCabinOverheatProtectionAction_init_default;
  cop_action.on = true;
  cop_action.fan_only = false;

  auto result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, &cop_action);
  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Building set cabin overheat protection via builder should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}
