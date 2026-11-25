#include <gtest/gtest.h>
#include <client.h>
#include <cstring>
#include <limits>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include <signatures.pb.h>
#include <car_server.pb.h>
#include "test_constants.h"

using namespace TeslaBLE;

// Mock data
static const char *const MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] =
    "-----BEGIN EC PRIVATE "
    "KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/"
    "lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+"
    "fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

class MessageBuildingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client = std::make_unique<Client>();
    client->set_vin(MOCK_VIN);

    // Load private key for message building
    int status =
        client->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                 strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    ASSERT_EQ(status, TeslaBLE_Status_E_OK) << "Failed to load private key for testing";

    // Set connection ID
    pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26,
                                   0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
    client->set_connection_id(connection_id);

    // Initialize VCSEC session for message building that requires encryption
    initialize_vcsec_session_();

    // Initialize Infotainment session for car server messages
    initialize_infotainment_session_();
  }

  void initialize_vcsec_session_() {
    // Parse the VCSEC message to get session info
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    auto parse_result = client->parse_universal_message(const_cast<pb_byte_t *>(TestConstants::MOCK_VCSEC_MESSAGE),
                                                        sizeof(TestConstants::MOCK_VCSEC_MESSAGE), &received_message);
    ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse VCSEC message";

    // Parse session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    auto session_parse_result =
        client->parse_payload_session_info(&received_message.payload.session_info, &session_info);
    ASSERT_EQ(session_parse_result, TeslaBLE_Status_E_OK) << "Failed to parse session info";

    // Get peer and update session
    auto *vcsec_peer = client->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

    auto update_result = vcsec_peer->update_session(&session_info);
    ASSERT_EQ(update_result, TeslaBLE_Status_E_OK) << "Updating VCSEC session should succeed";
    ASSERT_TRUE(vcsec_peer->is_initialized()) << "VCSEC peer should be initialized after update";
  }

  void initialize_infotainment_session_() {
    // Parse the Infotainment message to get session info
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    auto parse_result =
        client->parse_universal_message(const_cast<pb_byte_t *>(TestConstants::MOCK_INFOTAINMENT_MESSAGE),
                                        sizeof(TestConstants::MOCK_INFOTAINMENT_MESSAGE), &received_message);
    ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse Infotainment message";

    // Parse session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    auto session_parse_result =
        client->parse_payload_session_info(&received_message.payload.session_info, &session_info);
    ASSERT_EQ(session_parse_result, TeslaBLE_Status_E_OK) << "Failed to parse session info";

    // Get peer and update session
    auto *infotainment_peer = client->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    ASSERT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";

    auto update_result = infotainment_peer->update_session(&session_info);
    ASSERT_EQ(update_result, TeslaBLE_Status_E_OK) << "Updating Infotainment session should succeed";
    ASSERT_TRUE(infotainment_peer->is_initialized()) << "Infotainment peer should be initialized after update";
  }

  void TearDown() override { client.reset(); }

  std::unique_ptr<Client> client;
};

TEST_F(MessageBuildingTest, BuildWhiteListMessage) {
  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;

  auto result =
      client->build_white_list_message(Keys_Role_ROLE_CHARGING_MANAGER, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                       whitelist_message_buffer, &whitelist_message_length);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building whitelist message should succeed";
  EXPECT_GT(whitelist_message_length, 0) << "Whitelist message should have non-zero length";
  EXPECT_LE(whitelist_message_length, sizeof(whitelist_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECActionMessage) {
  unsigned char action_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t action_message_buffer_length = 0;

  auto result = client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, action_message_buffer,
                                                   &action_message_buffer_length);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building VCSEC action message should succeed";
  EXPECT_GT(action_message_buffer_length, 0) << "Action message should have non-zero length";
  EXPECT_LE(action_message_buffer_length, sizeof(action_message_buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildVCSECInformationRequestMessage) {
  pb_byte_t info_request_buffer[UniversalMessage_RoutableMessage_size];
  size_t info_request_length = 0;

  auto result = client->build_vcsec_information_request_message(
      VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, info_request_buffer, &info_request_length);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building VCSEC information request should succeed";
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

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building closure message should succeed";
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

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building closure message with multiple doors should succeed";
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
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Building message with null buffer should fail";

  // Test with null length pointer
  result = client->build_car_server_vehicle_action_message(buffer, nullptr,
                                                           CarServer_VehicleAction_setChargingAmpsAction_tag, &amps);
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Building message with null length pointer should fail";
}

// Individual tests for each vehicle data type - automatically generated from protobuf definition
class VehicleDataTest : public MessageBuildingTest {
 protected:
  struct VehicleDataTag {
    std::string name;
    int32_t tag;
  };

  static std::vector<VehicleDataTag> get_all_vehicle_data_tags() {
    std::vector<VehicleDataTag> all_vehicle_data_tags;

    // Extract field names and tag numbers from the nanopb FIELDLIST macro
    // clang-format off
#define EXTRACT_FIELD_INFO(a, type, label, datatype, name, tag_num) \
  all_vehicle_data_tags.emplace_back(VehicleDataTag{#name, CarServer_GetVehicleData_##name##_tag});

    CarServer_GetVehicleData_FIELDLIST(EXTRACT_FIELD_INFO, unused)
    // clang-format on

#undef EXTRACT_FIELD_INFO

        return all_vehicle_data_tags;
  }
};

TEST_F(VehicleDataTest, VehicleDataTagsAreUnique) {
  auto all_tags = get_all_vehicle_data_tags();

  // Verify tags are unique (no duplicates)
  std::set<int32_t> unique_tags;
  for (const auto &tag_info : all_tags) {
    ASSERT_TRUE(unique_tags.insert(tag_info.tag).second)
        << "Duplicate tag value " << tag_info.tag << " found for " << tag_info.name;
  }

  EXPECT_GT(all_tags.size(), 0) << "Should discover at least one vehicle data type";
}

// Generate individual test for each vehicle data type
#define GENERATE_VEHICLE_DATA_TEST(a, type, label, datatype, name, tag_num) \
  TEST_F(VehicleDataTest, VehicleData##name) { \
    pb_byte_t buffer[UniversalMessage_RoutableMessage_size]; \
    size_t length = 0; \
\
    auto result = \
        client->build_car_server_get_vehicle_data_message(buffer, &length, CarServer_GetVehicleData_##name##_tag); \
    EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building get vehicle data message for " #name " should succeed"; \
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
  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Building get vehicle data message with invalid type should fail";
}

// Helper function to get all vehicle action tags - shared across multiple tests
static std::vector<std::pair<std::string, int32_t>> get_all_vehicle_action_tags() {
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
      all_vehicle_action_tags.emplace_back(action_name_clean, tag_num); \
    } \
  }

  CarServer_VehicleAction_FIELDLIST(EXTRACT_VEHICLE_ACTION_INFO, unused)

#undef EXTRACT_VEHICLE_ACTION_INFO

      return all_vehicle_action_tags;
}

TEST_F(MessageBuildingTest, VehicleActionTagsAreUnique) {
  auto all_tags = get_all_vehicle_action_tags();

  // Verify tags are unique (no duplicates)
  std::set<int32_t> unique_tags;
  for (const auto &tag_pair : all_tags) {
    ASSERT_TRUE(unique_tags.insert(tag_pair.second).second)
        << "Duplicate tag value " << tag_pair.second << " found for " << tag_pair.first;
  }

  // Ensure we discovered a reasonable number of actions
  EXPECT_GE(all_tags.size(), 50) << "Should discover at least 50 vehicle actions from protobuf";

  std::cout << "Discovered " << all_tags.size() << " unique vehicle action types from protobuf\n";
}

// Test simple vehicle actions that don't require parameters
class VehicleActionSimpleTest : public MessageBuildingTest,
                                public ::testing::WithParamInterface<std::pair<std::string, int32_t>> {};

TEST_P(VehicleActionSimpleTest, BuildSimpleVehicleActionMessage) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto [action_name, tag] = GetParam();

  auto result = client->build_car_server_vehicle_action_message(buffer, &length, tag, nullptr);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK)
      << "Building simple vehicle action message " << action_name << " (" << tag << ") should succeed";
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
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building boolean vehicle action message " << action_name << " (" << tag
                                          << ") with value " << test_value << " should succeed";
  EXPECT_GT(length, 0) << "Vehicle action message should have non-zero length for " << action_name;
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer for " << action_name;
}

INSTANTIATE_TEST_SUITE_P(
    BooleanActions, VehicleActionBooleanTest,
    ::testing::Values(
        std::make_tuple("vehicleControlSetSentryModeAction_On",
                        CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, true),
        std::make_tuple("vehicleControlSetSentryModeAction_Off",
                        CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, false),
        std::make_tuple("hvacAutoAction_On", CarServer_VehicleAction_hvacAutoAction_tag, true),
        std::make_tuple("hvacAutoAction_Off", CarServer_VehicleAction_hvacAutoAction_tag, false),
        std::make_tuple("hvacSteeringWheelHeaterAction_On", CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag,
                        true),
        std::make_tuple("hvacSteeringWheelHeaterAction_Off", CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag,
                        false),
        std::make_tuple("setLowPowerModeAction_On", CarServer_VehicleAction_setLowPowerModeAction_tag, true),
        std::make_tuple("setLowPowerModeAction_Off", CarServer_VehicleAction_setLowPowerModeAction_tag, false),
        std::make_tuple("setKeepAccessoryPowerModeAction_On",
                        CarServer_VehicleAction_setKeepAccessoryPowerModeAction_tag, true),
        std::make_tuple("setKeepAccessoryPowerModeAction_Off",
                        CarServer_VehicleAction_setKeepAccessoryPowerModeAction_tag, false),
        std::make_tuple("guestModeAction_On", CarServer_VehicleAction_guestModeAction_tag, true),
        std::make_tuple("guestModeAction_Off", CarServer_VehicleAction_guestModeAction_tag, false)),
    [](const ::testing::TestParamInfo<VehicleActionBooleanTest::ParamType> &info) { return std::get<0>(info.param); });

// Test numeric vehicle actions
class VehicleActionNumericTest : public MessageBuildingTest,
                                 public ::testing::WithParamInterface<std::tuple<std::string, int32_t, int32_t>> {};

TEST_P(VehicleActionNumericTest, BuildNumericVehicleActionMessage) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  auto [action_name, tag, test_value] = GetParam();

  auto result = client->build_car_server_vehicle_action_message(buffer, &length, tag, &test_value);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building numeric vehicle action message " << action_name << " (" << tag
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
        std::make_tuple("ping_99999", CarServer_VehicleAction_ping_tag, 99999),
        std::make_tuple("setCopTempAction_Low", CarServer_VehicleAction_setCopTempAction_tag, 1),
        std::make_tuple("setCopTempAction_Medium", CarServer_VehicleAction_setCopTempAction_tag, 2),
        std::make_tuple("setCopTempAction_High", CarServer_VehicleAction_setCopTempAction_tag, 3)),
    [](const ::testing::TestParamInfo<VehicleActionNumericTest::ParamType> &info) { return std::get<0>(info.param); });

TEST_F(MessageBuildingTest, ScheduledDepartureBuildsAndValidatesTimes) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;
  CarServer_ScheduledDepartureAction departure = CarServer_ScheduledDepartureAction_init_default;
  departure.enabled = true;
  departure.departure_time = 7 * 60 + 30;
  departure.off_peak_hours_end_time = 6 * 60;
  departure.has_preconditioning_times = true;
  departure.preconditioning_times.which_times = CarServer_PreconditioningTimes_weekdays_tag;
  departure.has_off_peak_charging_times = true;
  departure.off_peak_charging_times.which_times = CarServer_OffPeakChargingTimes_all_week_tag;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_scheduledDepartureAction_tag, &departure),
            TeslaBLE_Status_E_OK);
  EXPECT_GT(length, 0);

  CarServer_ScheduledDepartureAction disable = CarServer_ScheduledDepartureAction_init_default;
  length = 0;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_scheduledDepartureAction_tag, &disable),
            TeslaBLE_Status_E_OK);

  departure.departure_time = 24 * 60;
  length = 0;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_scheduledDepartureAction_tag, &departure),
            TeslaBLE_Status_E_ERROR_INVALID_PARAMS);
}

TEST_F(MessageBuildingTest, AddPreconditionScheduleBuildsAndValidates) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;
  CarServer_PreconditionSchedule schedule = CarServer_PreconditionSchedule_init_default;
  schedule.id = 1764100000;
  schedule.days_of_week = 0x3E;
  schedule.precondition_time = 6 * 60 + 30;
  schedule.one_time = true;
  schedule.enabled = true;
  schedule.latitude = 37.39F;
  schedule.longitude = -122.15F;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_addPreconditionScheduleAction_tag, &schedule),
            TeslaBLE_Status_E_OK);
  EXPECT_GT(length, 0);

  auto expect_invalid = [&](CarServer_PreconditionSchedule bad) {
    length = 0;
    EXPECT_EQ(client->build_car_server_vehicle_action_message(
                  buffer, &length, CarServer_VehicleAction_addPreconditionScheduleAction_tag, &bad),
              TeslaBLE_Status_E_ERROR_INVALID_PARAMS);
  };
  auto bad = schedule;
  bad.id = 0;
  expect_invalid(bad);
  bad = schedule;
  bad.precondition_time = 24 * 60;
  expect_invalid(bad);
  bad = schedule;
  bad.days_of_week = 0;
  expect_invalid(bad);
  bad = schedule;
  bad.days_of_week = 0x80;
  expect_invalid(bad);
  bad = schedule;
  bad.latitude = 91.0F;
  expect_invalid(bad);
}

TEST_F(MessageBuildingTest, RemovePreconditionSchedulesBuildAndValidate) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;
  uint64_t id = 1764100000;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_removePreconditionScheduleAction_tag, &id),
            TeslaBLE_Status_E_OK);
  id = 0;
  length = 0;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_removePreconditionScheduleAction_tag, &id),
            TeslaBLE_Status_E_ERROR_INVALID_PARAMS);

  CarServer_BatchRemovePreconditionSchedulesAction batch =
      CarServer_BatchRemovePreconditionSchedulesAction_init_default;
  length = 0;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_batchRemovePreconditionSchedulesAction_tag, &batch),
            TeslaBLE_Status_E_ERROR_INVALID_PARAMS);
  batch.home = true;
  length = 0;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(
                buffer, &length, CarServer_VehicleAction_batchRemovePreconditionSchedulesAction_tag, &batch),
            TeslaBLE_Status_E_OK);
}

TEST_F(MessageBuildingTest, MediaUpdateVolumeBuildsAndValidates) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;
  CarServer_MediaUpdateVolume volume = CarServer_MediaUpdateVolume_init_default;

  volume.which_media_volume = CarServer_MediaUpdateVolume_volume_delta_tag;
  for (int32_t delta : {1, -1}) {
    volume.media_volume.volume_delta = delta;
    length = 0;
    EXPECT_EQ(client->build_car_server_vehicle_action_message(buffer, &length,
                                                              CarServer_VehicleAction_mediaUpdateVolume_tag, &volume),
              TeslaBLE_Status_E_OK)
        << "delta " << delta;
    EXPECT_GT(length, 0);
  }

  volume.which_media_volume = CarServer_MediaUpdateVolume_volume_absolute_float_tag;
  for (float level : {0.0f, 5.5f, 10.0f}) {
    volume.media_volume.volume_absolute_float = level;
    length = 0;
    EXPECT_EQ(client->build_car_server_vehicle_action_message(buffer, &length,
                                                              CarServer_VehicleAction_mediaUpdateVolume_tag, &volume),
              TeslaBLE_Status_E_OK)
        << "level " << level;
  }
  for (float level : {-0.5f, 10.5f, std::numeric_limits<float>::quiet_NaN()}) {
    volume.media_volume.volume_absolute_float = level;
    length = 0;
    EXPECT_EQ(client->build_car_server_vehicle_action_message(buffer, &length,
                                                              CarServer_VehicleAction_mediaUpdateVolume_tag, &volume),
              TeslaBLE_Status_E_ERROR_INVALID_PARAMS)
        << "level " << level << " should be rejected";
  }

  CarServer_MediaUpdateVolume empty = CarServer_MediaUpdateVolume_init_default;
  length = 0;
  EXPECT_EQ(client->build_car_server_vehicle_action_message(buffer, &length,
                                                            CarServer_VehicleAction_mediaUpdateVolume_tag, &empty),
            TeslaBLE_Status_E_ERROR_INVALID_PARAMS);
  EXPECT_EQ(client->build_car_server_vehicle_action_message(buffer, &length,
                                                            CarServer_VehicleAction_mediaUpdateVolume_tag, nullptr),
            TeslaBLE_Status_E_ERROR_INVALID_PARAMS);
}

TEST_F(MessageBuildingTest, SetCopTempRejectsOutOfRangeLevels) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  for (int32_t level : {0, 4, -1}) {
    size_t length = 0;
    auto result = client->build_car_server_vehicle_action_message(buffer, &length,
                                                                  CarServer_VehicleAction_setCopTempAction_tag, &level);
    EXPECT_EQ(result, TeslaBLE_Status_E_ERROR_INVALID_PARAMS) << "level " << level << " should be rejected";
  }
}

TEST_F(MessageBuildingTest, SetCabinOverheatProtectionOn) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  CarServer_SetCabinOverheatProtectionAction action = CarServer_SetCabinOverheatProtectionAction_init_default;
  action.on = true;
  action.fan_only = false;

  int result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, &action);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Setting cabin overheat protection ON should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, SetCabinOverheatProtectionOff) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  CarServer_SetCabinOverheatProtectionAction action = CarServer_SetCabinOverheatProtectionAction_init_default;
  action.on = false;
  action.fan_only = false;

  int result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, &action);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Setting cabin overheat protection OFF should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, SetCabinOverheatProtectionFanOnly) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  CarServer_SetCabinOverheatProtectionAction action = CarServer_SetCabinOverheatProtectionAction_init_default;
  action.on = true;
  action.fan_only = true;

  int result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, &action);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Setting cabin overheat protection fan_only should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, ScheduleSoftwareUpdate) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  CarServer_VehicleControlScheduleSoftwareUpdateAction action =
      CarServer_VehicleControlScheduleSoftwareUpdateAction_init_default;
  action.offset_sec = 3600;  // 1 hour from now

  int result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag, &action);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Scheduling software update should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, ScheduleSoftwareUpdateDelay) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  CarServer_VehicleControlScheduleSoftwareUpdateAction action =
      CarServer_VehicleControlScheduleSoftwareUpdateAction_init_default;
  action.offset_sec = 86400;  // 24 hours from now

  int result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag, &action);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Scheduling software update with 24h delay should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}

TEST_F(MessageBuildingTest, CancelSoftwareUpdate) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  int result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag, nullptr);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Canceling software update should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
  EXPECT_LE(length, sizeof(buffer)) << "Message should fit in buffer";
}

TEST_F(MessageBuildingTest, BuildScheduleSoftwareUpdateViaBuilder) {
  pb_byte_t buffer[UniversalMessage_RoutableMessage_size];
  size_t length = 0;

  int32_t offset_sec = 7200;  // 2 hours
  auto result = client->build_car_server_vehicle_action_message(
      buffer, &length, CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag, &offset_sec);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building schedule software update via builder should succeed";
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
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Building set cabin overheat protection via builder should succeed";
  EXPECT_GT(length, 0) << "Message should have non-zero length";
}
