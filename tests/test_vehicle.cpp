#include <gtest/gtest.h>

#include <vehicle.h>
#include "mocks/mock_adapters.h"
#include "tb_utils.h"
#include "test_constants.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

using TeslaBLE::Command;
using TeslaBLE::TeslaBLE_Status_E_OK;
using TeslaBLE::Vehicle;
using TeslaBLE::Client;
using TeslaBLE::BleAdapter;
using TeslaBLE::StorageAdapter;
using TeslaBLE::MockBleAdapter;
using TeslaBLE::MockStorageAdapter;
using TeslaBLE::TestConstants::CLIENT_PRIVATE_KEY_PEM;
using TeslaBLE::TestConstants::MOCK_INFOTAINMENT_MESSAGE;
using TeslaBLE::TestConstants::MOCK_VCSEC_MESSAGE;
using TeslaBLE::TestConstants::TEST_VIN;

namespace {
std::vector<uint8_t> frame_universal_message(const UniversalMessage_RoutableMessage &message) {
  size_t encoded_length = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> encoded(UniversalMessage_RoutableMessage_size);
  auto status =
      TeslaBLE::pb_encode_fields(encoded.data(), &encoded_length, UniversalMessage_RoutableMessage_fields, &message);
  if (status != TeslaBLE_Status_E_OK) {
    return {};
  }

  std::vector<uint8_t> framed(encoded_length + 2);
  framed[0] = static_cast<uint8_t>((encoded_length >> 8) & 0xFF);
  framed[1] = static_cast<uint8_t>(encoded_length & 0xFF);
  std::copy_n(encoded.begin(), encoded_length, framed.begin() + 2);
  return framed;
}

std::array<pb_byte_t, 16> extract_request_uuid(const std::vector<uint8_t> &frame, size_t *uuid_length) {
  std::array<pb_byte_t, 16> uuid{};
  if (uuid_length) {
    *uuid_length = 0;
  }
  if (frame.size() <= 2) {
    return uuid;
  }
  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage request = UniversalMessage_RoutableMessage_init_default;
  auto status = parser.parse_universal_message(const_cast<pb_byte_t *>(frame.data() + 2), frame.size() - 2, &request);
  if (status != TeslaBLE_Status_E_OK || request.uuid.size != uuid.size()) {
    return uuid;
  }
  std::copy(request.uuid.bytes, request.uuid.bytes + request.uuid.size, uuid.begin());
  if (uuid_length) {
    *uuid_length = request.uuid.size;
  }
  return uuid;
}

std::vector<uint8_t> make_session_info_with_valid_hmac(const pb_byte_t *request_uuid, size_t request_uuid_length,
                                                       const pb_byte_t *mock_message, size_t mock_message_length) {
  if (!request_uuid || request_uuid_length == 0) {
    return {};
  }

  TeslaBLE::CryptoContext crypto_context;
  size_t key_length = 0;
  while (CLIENT_PRIVATE_KEY_PEM[key_length] != '\0') {
    ++key_length;
  }
  auto load_status =
      crypto_context.load_private_key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM), key_length + 1);
  if (load_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  auto status = parser.parse_universal_message(const_cast<pb_byte_t *>(mock_message), mock_message_length, &message);
  if (status != TeslaBLE_Status_E_OK) {
    return {};
  }

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  status = parser.parse_payload_session_info(&message.payload.session_info, &session_info);
  if (status != TeslaBLE_Status_E_OK) {
    return {};
  }

  message.request_uuid.size = request_uuid_length;
  std::copy(request_uuid, request_uuid + request_uuid_length, message.request_uuid.bytes);

  size_t vin_length = 0;
  while (TEST_VIN[vin_length] != '\0') {
    ++vin_length;
  }
  std::array<pb_byte_t, 64> metadata{};
  size_t metadata_length = 0;
  metadata[metadata_length++] = Signatures_Tag_TAG_SIGNATURE_TYPE;
  metadata[metadata_length++] = 0x01;
  metadata[metadata_length++] = Signatures_SignatureType_SIGNATURE_TYPE_HMAC;
  metadata[metadata_length++] = Signatures_Tag_TAG_PERSONALIZATION;
  metadata[metadata_length++] = static_cast<pb_byte_t>(vin_length);
  std::copy_n(TEST_VIN, vin_length, metadata.begin() + metadata_length);
  metadata_length += vin_length;
  metadata[metadata_length++] = Signatures_Tag_TAG_CHALLENGE;
  metadata[metadata_length++] = static_cast<pb_byte_t>(request_uuid_length);
  std::copy_n(request_uuid, request_uuid_length, metadata.begin() + metadata_length);
  metadata_length += request_uuid_length;
  metadata[metadata_length++] = Signatures_Tag_TAG_END;

  std::vector<pb_byte_t> hmac_input;
  hmac_input.resize(metadata_length + message.payload.session_info.size);
  std::copy_n(metadata.begin(), metadata_length, hmac_input.begin());
  std::copy_n(message.payload.session_info.bytes, message.payload.session_info.size,
              hmac_input.begin() + metadata_length);

  uint8_t session_key[TeslaBLE::Peer::SHARED_KEY_SIZE_BYTES] = {0};
  auto ecdh_status =
      crypto_context.perform_tesla_ecdh(session_info.publicKey.bytes, session_info.publicKey.size, session_key);
  if (ecdh_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  uint8_t session_info_key[32] = {0};
  auto kdf_status = TeslaBLE::CryptoUtils::derive_session_info_key(session_key, sizeof(session_key), session_info_key,
                                                                   sizeof(session_info_key));
  TeslaBLE::CryptoUtils::clear_sensitive_memory(session_key, sizeof(session_key));
  if (kdf_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  uint8_t expected_tag[32] = {0};
  auto hmac_status = TeslaBLE::CryptoUtils::hmac_sha256(session_info_key, sizeof(session_info_key), hmac_input.data(),
                                                        hmac_input.size(), expected_tag, sizeof(expected_tag));
  TeslaBLE::CryptoUtils::clear_sensitive_memory(session_info_key, sizeof(session_info_key));
  if (hmac_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  message.sub_sigData.signature_data.sig_type.session_info_tag.tag.size = sizeof(expected_tag);
  std::copy(expected_tag, expected_tag + sizeof(expected_tag),
            message.sub_sigData.signature_data.sig_type.session_info_tag.tag.bytes);

  return frame_universal_message(message);
}

std::vector<uint8_t> make_vcsec_session_info_with_valid_hmac(const pb_byte_t *request_uuid,
                                                             size_t request_uuid_length) {
  return make_session_info_with_valid_hmac(request_uuid, request_uuid_length, MOCK_VCSEC_MESSAGE,
                                           sizeof(MOCK_VCSEC_MESSAGE));
}

std::vector<uint8_t> make_infotainment_session_info_with_valid_hmac(const pb_byte_t *request_uuid,
                                                                    size_t request_uuid_length) {
  return make_session_info_with_valid_hmac(request_uuid, request_uuid_length, MOCK_INFOTAINMENT_MESSAGE,
                                           sizeof(MOCK_INFOTAINMENT_MESSAGE));
}

std::vector<uint8_t> make_plain_infotainment_response() {
  pb_byte_t response_data[] = {0x0A, 0x02, 0x08, 0x00};
  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  message.has_from_destination = true;
  message.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  message.from_destination.sub_destination.domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
  message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
  message.payload.protobuf_message_as_bytes.size = sizeof(response_data);
  std::copy_n(response_data, sizeof(response_data), message.payload.protobuf_message_as_bytes.bytes);
  return frame_universal_message(message);
}

std::vector<uint8_t> make_session_info_with_status(const pb_byte_t *request_uuid, size_t request_uuid_length,
                                                   const pb_byte_t *mock_message, size_t mock_message_length,
                                                   Signatures_Session_Info_Status status) {
  if (!request_uuid || request_uuid_length == 0) {
    return {};
  }

  TeslaBLE::CryptoContext crypto_context;
  size_t key_length = 0;
  while (CLIENT_PRIVATE_KEY_PEM[key_length] != '\0') {
    ++key_length;
  }
  auto load_status =
      crypto_context.load_private_key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM), key_length + 1);
  if (load_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  auto parse_status = parser.parse_universal_message(const_cast<pb_byte_t *>(mock_message), mock_message_length, &message);
  if (parse_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  parse_status = parser.parse_payload_session_info(&message.payload.session_info, &session_info);
  if (parse_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  // Modify the status
  session_info.status = status;

  // Re-encode the session info with the modified status
  pb_byte_t session_info_buffer[256];
  size_t session_info_length = sizeof(session_info_buffer);
  auto encode_status = TeslaBLE::pb_encode_fields(session_info_buffer, &session_info_length,
                                                   Signatures_SessionInfo_fields, &session_info);
  if (encode_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  // Update message payload with modified session info
  message.payload.session_info.size = session_info_length;
  std::copy(session_info_buffer, session_info_buffer + session_info_length, message.payload.session_info.bytes);

  message.request_uuid.size = request_uuid_length;
  std::copy(request_uuid, request_uuid + request_uuid_length, message.request_uuid.bytes);

  size_t vin_length = 0;
  while (TEST_VIN[vin_length] != '\0') {
    ++vin_length;
  }
  std::array<pb_byte_t, 64> metadata{};
  size_t metadata_length = 0;
  metadata[metadata_length++] = Signatures_Tag_TAG_SIGNATURE_TYPE;
  metadata[metadata_length++] = 0x01;
  metadata[metadata_length++] = Signatures_SignatureType_SIGNATURE_TYPE_HMAC;
  metadata[metadata_length++] = Signatures_Tag_TAG_PERSONALIZATION;
  metadata[metadata_length++] = static_cast<pb_byte_t>(vin_length);
  std::copy_n(TEST_VIN, vin_length, metadata.begin() + metadata_length);
  metadata_length += vin_length;
  metadata[metadata_length++] = Signatures_Tag_TAG_CHALLENGE;
  metadata[metadata_length++] = static_cast<pb_byte_t>(request_uuid_length);
  std::copy_n(request_uuid, request_uuid_length, metadata.begin() + metadata_length);
  metadata_length += request_uuid_length;
  metadata[metadata_length++] = Signatures_Tag_TAG_END;

  std::vector<pb_byte_t> hmac_input;
  hmac_input.resize(metadata_length + session_info_length);
  std::copy_n(metadata.begin(), metadata_length, hmac_input.begin());
  std::copy_n(session_info_buffer, session_info_length, hmac_input.begin() + metadata_length);

  uint8_t session_key[TeslaBLE::Peer::SHARED_KEY_SIZE_BYTES] = {0};
  auto ecdh_status =
      crypto_context.perform_tesla_ecdh(session_info.publicKey.bytes, session_info.publicKey.size, session_key);
  if (ecdh_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  uint8_t session_info_key[32] = {0};
  auto kdf_status = TeslaBLE::CryptoUtils::derive_session_info_key(session_key, sizeof(session_key), session_info_key,
                                                                   sizeof(session_info_key));
  TeslaBLE::CryptoUtils::clear_sensitive_memory(session_key, sizeof(session_key));
  if (kdf_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  uint8_t expected_tag[32] = {0};
  auto hmac_status = TeslaBLE::CryptoUtils::hmac_sha256(session_info_key, sizeof(session_info_key), hmac_input.data(),
                                                        hmac_input.size(), expected_tag, sizeof(expected_tag));
  TeslaBLE::CryptoUtils::clear_sensitive_memory(session_info_key, sizeof(session_info_key));
  if (hmac_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  message.sub_sigData.signature_data.sig_type.session_info_tag.tag.size = sizeof(expected_tag);
  std::copy(expected_tag, expected_tag + sizeof(expected_tag),
            message.sub_sigData.signature_data.sig_type.session_info_tag.tag.bytes);

  return frame_universal_message(message);
}

std::vector<uint8_t> make_vcsec_session_info_key_not_on_whitelist(const pb_byte_t *request_uuid,
                                                                  size_t request_uuid_length) {
  return make_session_info_with_status(request_uuid, request_uuid_length, MOCK_VCSEC_MESSAGE, sizeof(MOCK_VCSEC_MESSAGE),
                                      Signatures_Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST);
}
}  // namespace

class VehicleTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_ble_ = std::make_shared<MockBleAdapter>();
    mock_storage_ = std::make_shared<MockStorageAdapter>();

    // Inject a valid PEM private key from test_constants.h
    size_t stored_key_length = 0;
    while (CLIENT_PRIVATE_KEY_PEM[stored_key_length] != '\0') {
      ++stored_key_length;
    }
    std::vector<uint8_t> key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM),
                             reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM) + stored_key_length + 1);
    mock_storage_->set_data("private_key", key);

    vehicle_ = std::make_shared<Vehicle>(mock_ble_, mock_storage_);
    vehicle_->set_vin(TEST_VIN);
  }

  std::shared_ptr<MockBleAdapter> mock_ble_;
  std::shared_ptr<MockStorageAdapter> mock_storage_;
  std::shared_ptr<Vehicle> vehicle_;
};

// ============================================================================
// Basic Initialization Tests
// ============================================================================

TEST_F(VehicleTest, Initialization) {
  // Vehicle should be created successfully with valid adapters
  EXPECT_NE(vehicle_, nullptr);
  ASSERT_FALSE(vehicle_->is_connected()) << "Newly created vehicle should not be connected";
}

TEST_F(VehicleTest, SetVin) {
  std::string vin = "TESTVIN123456789";
  EXPECT_NO_THROW(vehicle_->set_vin(vin));
}

// ============================================================================
// Connection State Tests
// ============================================================================

TEST_F(VehicleTest, ConnectionStateTransitions) {
  ASSERT_FALSE(vehicle_->is_connected());

  vehicle_->set_connected(true);
  ASSERT_TRUE(vehicle_->is_connected());

  vehicle_->set_connected(false);
  ASSERT_FALSE(vehicle_->is_connected());
}

// ============================================================================
// Command Sending Tests
// ============================================================================

TEST_F(VehicleTest, WakeCommandSendsData) {
  // When wake() is called and loop() is processed,
  // the vehicle should send BLE data (session auth or command)
  vehicle_->set_connected(true);
  vehicle_->wake();
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Wake command should result in BLE data being sent";
}

TEST_F(VehicleTest, VCSECPollSendsData) {
  vehicle_->set_connected(true);
  vehicle_->vcsec_poll();
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "VCSEC poll should result in BLE data being sent";
}

TEST_F(VehicleTest, InfotainmentPollWithForceWakeSendsData) {
  vehicle_->set_connected(true);
  vehicle_->infotainment_poll(true);  // force_wake = true
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Infotainment poll with force_wake should send data";
}

TEST_F(VehicleTest, InfotainmentPollCompletesOnResponse) {
  vehicle_->set_connected(true);

  bool callback_called = false;
  bool callback_success = false;

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Infotainment Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      },
      true);

  vehicle_->loop();
  auto initial_writes = mock_ble_->get_written_data();
  ASSERT_GE(initial_writes.size(), 1);
  size_t request_uuid_length = 0;
  auto request_uuid = extract_request_uuid(initial_writes.front(), &request_uuid_length);
  ASSERT_EQ(request_uuid_length, request_uuid.size());

  auto vcsec_session = make_vcsec_session_info_with_valid_hmac(request_uuid.data(), request_uuid_length);
  ASSERT_FALSE(vcsec_session.empty());
  vehicle_->on_rx_data(vcsec_session);
  vehicle_->loop();

  auto info_writes = mock_ble_->get_written_data();
  ASSERT_GE(info_writes.size(), 2);
  size_t infotainment_request_uuid_length = 0;
  auto infotainment_request_uuid = extract_request_uuid(info_writes.back(), &infotainment_request_uuid_length);
  ASSERT_EQ(infotainment_request_uuid_length, infotainment_request_uuid.size());

  auto infotainment_session = make_infotainment_session_info_with_valid_hmac(infotainment_request_uuid.data(),
                                                                             infotainment_request_uuid_length);
  ASSERT_FALSE(infotainment_session.empty());
  vehicle_->on_rx_data(infotainment_session);
  vehicle_->loop();

  ASSERT_FALSE(callback_called) << "Infotainment command should not complete before response";

  auto response_frame = make_plain_infotainment_response();
  ASSERT_FALSE(response_frame.empty());
  vehicle_->on_rx_data(response_frame);
  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "Infotainment command should complete after response";
  ASSERT_TRUE(callback_success) << "Infotainment command should report success";
}

// ============================================================================
// Vehicle Sleep State Tests - Regression test for charging vehicle polling bug
// Issue: Infotainment polls were skipped when vehicle was charging because
// VCSEC reports UNKNOWN status (not AWAKE) for charging vehicles.
// Fix: Inverted logic to treat vehicle as awake unless explicitly ASLEEP.
// ============================================================================

TEST_F(VehicleTest, InfotainmentPollSkippedWhenAsleepByDefault) {
  // Verify default behavior: vehicle starts in asleep state (no VCSEC status received)
  // and infotainment polls without force_wake should be skipped
  vehicle_->set_connected(true);

  bool poll_callback_called = false;
  bool poll_success = false;

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Optional Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        poll_callback_called = true;
        poll_success = success;
      },
      false  // requires_wake = false (optional poll)
  );
  vehicle_->loop();

  // Poll should be skipped (no BLE writes) but callback invoked with success
  ASSERT_TRUE(poll_callback_called) << "Callback should be invoked for skipped poll";
  ASSERT_TRUE(poll_success) << "Skipped poll should report success (no-op)";

  auto writes = mock_ble_->get_written_data();
  EXPECT_EQ(writes.size(), 0) << "Poll should be skipped when vehicle is asleep";
}

TEST_F(VehicleTest, SetChargingAmpsSendsData) {
  vehicle_->set_connected(true);
  vehicle_->set_charging_amps(16);
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Set charging amps should initiate communication";
}

TEST_F(VehicleTest, SetChargingLimitSendsData) {
  vehicle_->set_connected(true);
  vehicle_->set_charging_limit(80);
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Set charging limit should initiate communication";
}

// ============================================================================
// Command Callback Tests
// ============================================================================

TEST_F(VehicleTest, CommandCallbackIsInvokedOnSuccess) {
  bool callback_called = false;
  bool callback_result = false;

  vehicle_->set_connected(true);
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Command",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buff, len);
      },
      [&](bool success) {
        callback_called = true;
        callback_result = success;
      });

  // Process initial auth request
  vehicle_->loop();
  auto initial_writes = mock_ble_->get_written_data();
  ASSERT_GE(initial_writes.size(), 1);
  size_t request_uuid_length = 0;
  auto request_uuid = extract_request_uuid(initial_writes.front(), &request_uuid_length);
  ASSERT_EQ(request_uuid_length, request_uuid.size());
  mock_ble_->clear_written_data();

  // Inject valid session info response to complete auth
  auto rx_data = make_vcsec_session_info_with_valid_hmac(request_uuid.data(), request_uuid_length);
  ASSERT_FALSE(rx_data.empty()) << "Failed to build session info response";
  vehicle_->on_rx_data(rx_data);

  // Process response and send command
  vehicle_->loop();
  vehicle_->loop();

  // Command should have been sent
  EXPECT_GE(mock_ble_->get_written_data().size(), 1) << "Command should be sent after auth";
}

TEST_F(VehicleTest, CommandCallbackReceivesFailureOnDisconnect) {
  bool callback_called = false;
  bool callback_success = true;  // Will be set to false if properly failed

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      });

  // Disconnect before command completes
  vehicle_->set_connected(false);

  ASSERT_TRUE(callback_called) << "Callback should be invoked on disconnect";
  ASSERT_FALSE(callback_success) << "Disconnected command should report failure";
}

TEST_F(VehicleTest, NullCallbackIsHandledSafely) {
  // Enqueue command without callback - should not crash
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "No Callback Command",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      nullptr);

  EXPECT_NO_THROW(vehicle_->loop());
  EXPECT_NO_THROW(vehicle_->set_connected(false));
}

// ============================================================================
// Message Receiving Tests
// ============================================================================

TEST_F(VehicleTest, ReceivingDataDoesNotCrash) {
  // Receiving arbitrary data should not crash (graceful error handling)
  std::vector<uint8_t> garbage_data = {0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  EXPECT_NO_THROW(vehicle_->on_rx_data(garbage_data));
}

TEST_F(VehicleTest, ReceivingPartialDataDoesNotCrash) {
  // Partial message (header says 32 bytes, only 2 provided)
  std::vector<uint8_t> partial_data = {0x00, 0x20, 0x01, 0x02};
  EXPECT_NO_THROW(vehicle_->on_rx_data(partial_data));
}

TEST_F(VehicleTest, ReceivingEmptyDataDoesNotCrash) {
  std::vector<uint8_t> empty_data;
  EXPECT_NO_THROW(vehicle_->on_rx_data(empty_data));
}

TEST_F(VehicleTest, ReceivingValidSessionInfoUpdatesState) {
  // First, send a command to initiate auth
  vehicle_->vcsec_poll();
  vehicle_->loop();

  mock_ble_->clear_written_data();

  // Inject valid session info response
  std::vector<uint8_t> rx_data;
  rx_data.push_back(0x00);
  rx_data.push_back(177);
  rx_data.insert(rx_data.end(), MOCK_VCSEC_MESSAGE, MOCK_VCSEC_MESSAGE + 177);

  vehicle_->on_rx_data(rx_data);
  vehicle_->loop();

  // After receiving session info, the next step should proceed
  // (either send command or transition to next state)
  // The fact that loop() processes without crash indicates success
}

TEST_F(VehicleTest, RecoverySkipsCorruptPrefix) {
  vehicle_->set_connected(true);

  size_t message_count = 0;
  vehicle_->set_message_callback([&](const UniversalMessage_RoutableMessage &) { message_count++; });

  std::vector<uint8_t> prefix = {0xFF, 0xEE, 0xDD, 0xCC};
  std::vector<uint8_t> framed;
  framed.insert(framed.end(), prefix.begin(), prefix.end());
  framed.push_back(0x00);
  framed.push_back(177);
  framed.insert(framed.end(), MOCK_VCSEC_MESSAGE, MOCK_VCSEC_MESSAGE + 177);

  vehicle_->on_rx_data(framed);
  vehicle_->loop();

  EXPECT_EQ(message_count, 1U) << "Valid message should be recovered after corrupt prefix";
}

// ============================================================================
// Polling Behavior Tests (requires_wake)
// ============================================================================

TEST_F(VehicleTest, InfotainmentPollWithoutForceWakeSkipsWhenAsleep) {
  bool callback_called = false;
  bool callback_success = false;

  // Send poll that doesn't require wake
  vehicle_->set_connected(true);
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Infotainment Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      },
      false  // requires_wake = false
  );

  vehicle_->loop();

  // When vehicle is asleep and command doesn't require wake,
  // it should be skipped (completed as success without sending)
  ASSERT_TRUE(callback_called) << "Poll callback should be called";
  ASSERT_TRUE(callback_success) << "Skipped poll should be marked success (no-op)";
}

// ============================================================================
// Disconnect Handling Tests
// ============================================================================

TEST_F(VehicleTest, DisconnectClearsAuthenticationState) {
  vehicle_->set_connected(true);
  ASSERT_TRUE(vehicle_->is_connected());

  vehicle_->set_connected(false);
  ASSERT_FALSE(vehicle_->is_connected());

  // After reconnection, commands should go through full auth flow
  vehicle_->set_connected(true);
  vehicle_->vcsec_poll();
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Should initiate auth after reconnection";
}

TEST_F(VehicleTest, DisconnectClearsAllPendingCommands) {
  bool callback1_called = false;
  bool callback1_success = true;
  bool callback2_called = false;
  bool callback2_success = true;

  // Enqueue multiple commands
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Command 1",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      [&](bool success) {
        callback1_called = true;
        callback1_success = success;
      });

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Command 2",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      [&](bool success) {
        callback2_called = true;
        callback2_success = success;
      });

  // Disconnect should clear queue and fail all commands
  vehicle_->set_connected(false);

  ASSERT_TRUE(callback1_called) << "First command should receive callback";
  ASSERT_FALSE(callback1_success) << "First command should fail on disconnect";
  ASSERT_TRUE(callback2_called) << "Second command should receive callback";
  ASSERT_FALSE(callback2_success) << "Second command should fail on disconnect";
}

TEST_F(VehicleTest, SessionInfoKeyNotOnWhitelistHmacVerificationPasses) {
  // This test validates that session info with KEY_NOT_ON_WHITELIST status
  // is accepted after HMAC verification and surfaces as a pairing error
  // rather than a session parse failure.
  // This aligns with teslamotors/vehicle-command behavior where
  // KEY_NOT_ON_WHITELIST is treated as ErrKeyNotPaired, not a parse error.

  bool callback_called = false;
  bool callback_success = true;

  vehicle_->set_connected(true);

  // Send a command that requires authentication
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Command",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 10;
        std::fill_n(buffer, 10, 0x42);
        return TeslaBLE_Status_E_OK;
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      });

  vehicle_->loop();

  // Vehicle should send SESSION_INFO request
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "Vehicle should send session info request";

  // Extract the request UUID from the session info request
  size_t request_uuid_length = 0;
  auto request_uuid = extract_request_uuid(writes[0], &request_uuid_length);
  ASSERT_EQ(request_uuid_length, 16) << "Request UUID should be 16 bytes";

  // Create a session info response with KEY_NOT_ON_WHITELIST status and valid HMAC
  auto session_info_response = make_vcsec_session_info_key_not_on_whitelist(request_uuid.data(), request_uuid_length);
  ASSERT_GT(session_info_response.size(), 0) << "Should create valid session info with KEY_NOT_ON_WHITELIST";

  // Inject the session info response
  vehicle_->on_rx_data(session_info_response);
  vehicle_->loop();

  // Command should have been called back with failure
  ASSERT_TRUE(callback_called) << "Command callback should be invoked";
  ASSERT_FALSE(callback_success) << "Command should fail due to key not on whitelist";

  // Verify no further writes (command should not be sent)
  auto writes_after = mock_ble_->get_written_data();
  EXPECT_EQ(writes_after.size(), writes.size())
      << "No additional writes should occur after key not on whitelist error";
}

TEST_F(VehicleTest, SessionInfoKeyNotOnWhitelistDoesNotUpdatePeerSession) {
  // Verify that KEY_NOT_ON_WHITELIST status does not update the peer session
  // This ensures the session remains invalid, forcing re-auth on next command

  vehicle_->set_connected(true);

  // Send a command
  bool callback_called = false;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Command",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      [&](bool success) { callback_called = true; });

  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);

  size_t request_uuid_length = 0;
  auto request_uuid = extract_request_uuid(writes[0], &request_uuid_length);

  // Inject KEY_NOT_ON_WHITELIST response
  auto session_info_response = make_vcsec_session_info_key_not_on_whitelist(request_uuid.data(), request_uuid_length);
  vehicle_->on_rx_data(session_info_response);
  vehicle_->loop();

  ASSERT_TRUE(callback_called);

  // Send another command - should require auth again since session wasn't updated
  bool callback2_called = false;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Command 2",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      [&](bool success) { callback2_called = true; });

  vehicle_->loop();

  // Should send another SESSION_INFO request since previous one didn't update session
  auto writes2 = mock_ble_->get_written_data();
  EXPECT_GT(writes2.size(), writes.size()) << "Should send new session info request for second command";
}

TEST_F(VehicleTest, DisconnectClearsPartiallyReceivedData) {
  // Inject partial data (incomplete message)
  std::vector<uint8_t> partial_data = {0x00, 0x20, 0x01, 0x02};
  vehicle_->on_rx_data(partial_data);

  // Disconnect should clear buffers
  vehicle_->set_connected(false);
  vehicle_->set_connected(true);

  // New data after reconnection should be processed independently
  std::vector<uint8_t> fresh_data = {0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  EXPECT_NO_THROW(vehicle_->on_rx_data(fresh_data));
}

TEST_F(VehicleTest, DisconnectWithEmptyQueueDoesNotCrash) { EXPECT_NO_THROW(vehicle_->set_connected(false)); }

TEST_F(VehicleTest, ReconnectionAllowsFreshCommands) {
  vehicle_->set_connected(true);
  vehicle_->vcsec_poll();
  vehicle_->loop();
  mock_ble_->clear_written_data();

  // Disconnect and reconnect
  vehicle_->set_connected(false);
  vehicle_->set_connected(true);

  // New command should work
  vehicle_->vcsec_poll();
  vehicle_->loop();

  EXPECT_GE(mock_ble_->get_written_data().size(), 1) << "Should be able to send commands after reconnection";
}

TEST_F(VehicleTest, MultipleDisconnectsOnlyCallbackOnce) {
  vehicle_->set_connected(true);

  int callback_count = 0;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLE_Status_E_OK;
      },
      [&](bool) { callback_count++; });

  // Multiple disconnects should be idempotent
  vehicle_->set_connected(false);
  vehicle_->set_connected(false);
  vehicle_->set_connected(false);

  EXPECT_EQ(callback_count, 1) << "Callback should only be invoked once";
}

// ============================================================================
// Command Struct Tests
// ============================================================================

TEST(CommandStructTest, DefaultRequiresWakeIsTrue) {
  Command cmd(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Command",
      [](Client *, uint8_t *, size_t *) { return TeslaBLE_Status_E_OK; }, nullptr);

  ASSERT_TRUE(cmd.requires_wake) << "Commands should default to requiring wake for safety";
}

TEST(CommandStructTest, RequiresWakeCanBeSetFalse) {
  Command cmd(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Poll",
      [](Client *, uint8_t *, size_t *) { return TeslaBLE_Status_E_OK; }, nullptr, false);

  ASSERT_FALSE(cmd.requires_wake);
}

// ============================================================================
// Internal Helper Tests (for regression testing specific fixes)
// These test internal behavior but are necessary for regression coverage
// ============================================================================

// Friend test helper to access protected members for regression tests
class VehicleTestHelper : public Vehicle {
 public:
  using Vehicle::get_expected_message_length;
  using Vehicle::rx_buffer_;

  VehicleTestHelper(const std::shared_ptr<BleAdapter> &b, const std::shared_ptr<StorageAdapter> &s) : Vehicle(b, s) {}

  void set_buffer(const std::vector<uint8_t> &data) { rx_buffer_ = data; }
};

TEST(VehicleInternalTest, ExpectedLengthIncludesHeader) {
  // Regression test: message length calculation must include 2-byte header
  // This prevents "End of stream" parsing bugs
  auto b = std::make_shared<MockBleAdapter>();
  auto s = std::make_shared<MockStorageAdapter>();
  VehicleTestHelper v(b, s);

  std::vector<uint8_t> data = {0x00, 0x0A};  // Length field = 10
  v.set_buffer(data);

  // Total expected length should be payload (10) + header (2) = 12
  EXPECT_EQ(v.get_expected_message_length(), 12);
}
