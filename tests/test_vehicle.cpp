#include <gtest/gtest.h>

#include <vehicle.h>
#include "mocks/mock_adapters.h"
#include "tb_utils.h"
#include "test_constants.h"

#include <pb_decode.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

using TeslaBLE::Command;
using TeslaBLE::CommandError;
using TeslaBLE::CommandState;
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

std::vector<uint8_t> make_plain_infotainment_action_error_response(const char *reason) {
  CarServer_Response response = CarServer_Response_init_default;
  response.has_actionStatus = true;
  response.actionStatus.result = CarServer_OperationStatus_E_OPERATIONSTATUS_ERROR;

  if (reason && reason[0] != '\0') {
    response.actionStatus.has_result_reason = true;
    response.actionStatus.result_reason.which_reason = CarServer_ResultReason_plain_text_tag;
    std::strncpy(response.actionStatus.result_reason.reason.plain_text, reason,
                 sizeof(response.actionStatus.result_reason.reason.plain_text) - 1);
    response.actionStatus.result_reason.reason
        .plain_text[sizeof(response.actionStatus.result_reason.reason.plain_text) - 1] = '\0';
  }

  pb_byte_t response_buffer[256];
  size_t response_length = sizeof(response_buffer);
  auto encode_status =
      TeslaBLE::pb_encode_fields(response_buffer, &response_length, CarServer_Response_fields, &response);
  if (encode_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  message.has_from_destination = true;
  message.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  message.from_destination.sub_destination.domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
  message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
  message.payload.protobuf_message_as_bytes.size = response_length;
  std::copy_n(response_buffer, response_length, message.payload.protobuf_message_as_bytes.bytes);
  return frame_universal_message(message);
}

std::vector<uint8_t> make_session_info_with_status(const pb_byte_t *request_uuid, size_t request_uuid_length,
                                                   const pb_byte_t *mock_message, size_t mock_message_length,
                                                   Signatures_Session_Info_Status status) {
  if (!request_uuid || request_uuid_length == 0) {
    return {};
  }

  TeslaBLE::CryptoContext crypto_context;
  auto load_status = crypto_context.load_private_key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM),
                                                     strlen(CLIENT_PRIVATE_KEY_PEM) + 1);
  if (load_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  auto parse_status =
      parser.parse_universal_message(const_cast<pb_byte_t *>(mock_message), mock_message_length, &message);
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

  size_t vin_length = strlen(TEST_VIN);
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
  return make_session_info_with_status(request_uuid, request_uuid_length, MOCK_VCSEC_MESSAGE,
                                       sizeof(MOCK_VCSEC_MESSAGE),
                                       Signatures_Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST);
}

bool parse_whitelist_message(const std::vector<uint8_t> &frame, VCSEC_PermissionChange *permissions,
                             VCSEC_KeyFormFactor *form_factor, VCSEC_SignatureType *signature_type) {
  if (frame.size() <= 2) {
    return false;
  }

  VCSEC_ToVCSECMessage vcsec_message = VCSEC_ToVCSECMessage_init_default;
  pb_istream_t vcsec_stream = pb_istream_from_buffer(frame.data() + 2, frame.size() - 2);
  if (!pb_decode(&vcsec_stream, VCSEC_ToVCSECMessage_fields, &vcsec_message) || !vcsec_message.has_signedMessage) {
    return false;
  }

  if (signature_type) {
    *signature_type = vcsec_message.signedMessage.signatureType;
  }

  VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
  pb_istream_t payload_stream = pb_istream_from_buffer(vcsec_message.signedMessage.protobufMessageAsBytes.bytes,
                                                       vcsec_message.signedMessage.protobufMessageAsBytes.size);
  if (!pb_decode(&payload_stream, VCSEC_UnsignedMessage_fields, &unsigned_message) ||
      unsigned_message.which_sub_message != VCSEC_UnsignedMessage_WhitelistOperation_tag) {
    return false;
  }

  const auto &whitelist = unsigned_message.sub_message.WhitelistOperation;
  if (whitelist.which_sub_message != VCSEC_WhitelistOperation_addKeyToWhitelistAndAddPermissions_tag) {
    return false;
  }

  if (permissions) {
    *permissions = whitelist.sub_message.addKeyToWhitelistAndAddPermissions;
  }
  if (form_factor) {
    *form_factor = whitelist.metadataForKey.keyFormFactor;
  }

  return true;
}

std::vector<uint8_t> derive_public_key_from_private_key(const std::vector<uint8_t> &private_key) {
  TeslaBLE::CryptoContext crypto_context;
  if (crypto_context.load_private_key(private_key.data(), private_key.size()) != TeslaBLE_Status_E_OK) {
    return {};
  }

  std::array<pb_byte_t, 128> public_key{};
  size_t public_key_length = public_key.size();
  if (crypto_context.generate_public_key(public_key.data(), &public_key_length) != TeslaBLE_Status_E_OK) {
    return {};
  }

  return {public_key.begin(), public_key.begin() + public_key_length};
}

std::vector<uint8_t> make_session_info_no_hmac_tag(UniversalMessage_Domain domain) {
  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage mock_msg = UniversalMessage_RoutableMessage_init_default;
  auto status = parser.parse_universal_message(const_cast<pb_byte_t *>(MOCK_VCSEC_MESSAGE), sizeof(MOCK_VCSEC_MESSAGE),
                                               &mock_msg);
  if (status != TeslaBLE_Status_E_OK) {
    return {};
  }

  UniversalMessage_RoutableMessage response = UniversalMessage_RoutableMessage_init_default;

  response.has_from_destination = true;
  response.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  response.from_destination.sub_destination.domain = domain;

  response.which_payload = UniversalMessage_RoutableMessage_session_info_tag;
  std::copy_n(mock_msg.payload.session_info.bytes, mock_msg.payload.session_info.size,
              response.payload.session_info.bytes);
  response.payload.session_info.size = mock_msg.payload.session_info.size;

  return frame_universal_message(response);
}

std::vector<uint8_t> make_vcsec_vehicle_status_awake_message() {
  VCSEC_FromVCSECMessage vcsec_message = VCSEC_FromVCSECMessage_init_default;
  vcsec_message.which_sub_message = VCSEC_FromVCSECMessage_vehicleStatus_tag;

  auto &status = vcsec_message.sub_message.vehicleStatus;
  status.has_closureStatuses = true;
  status.closureStatuses.chargePort = VCSEC_ClosureState_E_CLOSURESTATE_OPEN;
  status.vehicleLockState = VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_LOCKED;
  status.vehicleSleepStatus = VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_AWAKE;
  status.userPresence = VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT;

  pb_byte_t vcsec_buffer[256];
  size_t vcsec_length = sizeof(vcsec_buffer);
  auto status_code =
      TeslaBLE::pb_encode_fields(vcsec_buffer, &vcsec_length, VCSEC_FromVCSECMessage_fields, &vcsec_message);
  if (status_code != TeslaBLE_Status_E_OK) {
    return {};
  }

  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  message.has_to_destination = true;
  message.to_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
  message.to_destination.sub_destination.routing_address.size = 16;

  message.has_from_destination = true;
  message.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  message.from_destination.sub_destination.domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;

  message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
  message.payload.protobuf_message_as_bytes.size = vcsec_length;
  std::copy_n(vcsec_buffer, vcsec_length, message.payload.protobuf_message_as_bytes.bytes);

  return frame_universal_message(message);
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
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Awake);

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

TEST_F(VehicleTest, InfotainmentActionFailureSurfacesPlainTextReason) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Awake);

  bool callback_called = false;
  std::unique_ptr<CommandError> captured_error;

  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Climate On",
      [](Client *client, uint8_t *buff, size_t *len) {
        bool enabled = true;
        return client->build_car_server_vehicle_action_message(buff, len, CarServer_VehicleAction_hvacAutoAction_tag,
                                                               &enabled);
      },
      [&](std::unique_ptr<CommandError> error) {
        callback_called = true;
        captured_error = std::move(error);
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

  auto action_error_frame = make_plain_infotainment_action_error_response("climate keeper unavailable");
  ASSERT_FALSE(action_error_frame.empty());
  vehicle_->on_rx_data(action_error_frame);
  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "Infotainment action should complete with failure";
  ASSERT_NE(captured_error, nullptr) << "Infotainment action should surface an error";
  EXPECT_FALSE(captured_error->is_temporary()) << "CarServer action failures should be permanent";
  EXPECT_FALSE(captured_error->may_have_succeeded()) << "CarServer action failures should be definite failures";
  EXPECT_TRUE(captured_error->message().find("climate keeper unavailable") != std::string::npos)
      << "Error should include the vehicle-provided action failure reason: " << captured_error->message();
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
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

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

  // Poll should be skipped (no BLE writes) but callback invoked with compatible_success()
  ASSERT_TRUE(poll_callback_called) << "Callback should be invoked for skipped poll";
  ASSERT_TRUE(poll_success) << "Skipped poll should report compatible_success (no-op)";

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

TEST_F(VehicleTest, ReceivingValidSessionInfoCompletesAuth) {
  vehicle_->set_connected(true);

  bool callback_called = false;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 4;
        std::fill_n(buffer, 4, 0x42);
        return TeslaBLE_Status_E_OK;
      },
      [&](bool) { callback_called = true; });

  vehicle_->loop();

  // Extract the request UUID from the session info request
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);
  size_t request_uuid_length = 0;
  auto request_uuid = extract_request_uuid(writes[0], &request_uuid_length);
  ASSERT_EQ(request_uuid_length, 16);

  // Build a valid session info response with matching HMAC
  auto session_resp = make_vcsec_session_info_with_valid_hmac(request_uuid.data(), request_uuid_length);
  ASSERT_GT(session_resp.size(), 0);

  vehicle_->on_rx_data(session_resp);
  vehicle_->loop();

  // Auth should complete and command should be sent
  auto writes_after = mock_ble_->get_written_data();
  EXPECT_GT(writes_after.size(), writes.size()) << "Command should be sent after successful auth";

  // Verify no crash on disconnect after successful auth
  EXPECT_NO_THROW(vehicle_->set_connected(false));
  EXPECT_TRUE(callback_called) << "Disconnect should invoke callback";
}

TEST_F(VehicleTest, RecoverySkipsCorruptPrefix) {
  vehicle_->set_connected(true);

  size_t message_count = 0;
  vehicle_->set_message_callback([&](const UniversalMessage_RoutableMessage &) { message_count++; });

  std::vector<uint8_t> prefix = {0xFF, 0xEE, 0xDD, 0xCC};
  std::vector<uint8_t> framed;
  framed.insert(framed.end(), prefix.begin(), prefix.end());
  framed.push_back(0x00);
  framed.push_back(sizeof(MOCK_VCSEC_MESSAGE));
  framed.insert(framed.end(), MOCK_VCSEC_MESSAGE, MOCK_VCSEC_MESSAGE + sizeof(MOCK_VCSEC_MESSAGE));

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
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);
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
  EXPECT_EQ(writes_after.size(), writes.size()) << "No additional writes should occur after key not on whitelist error";
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

TEST(VehiclePairingTest, PairPersistsGeneratedKeyAndSendsDirectWhitelistRequest) {
  auto ble = std::make_shared<MockBleAdapter>();
  auto storage = std::make_shared<MockStorageAdapter>();
  auto vehicle = std::make_shared<Vehicle>(ble, storage);

  vehicle->set_vin(TEST_VIN);
  vehicle->set_connected(true);
  vehicle->pair(Keys_Role_ROLE_DRIVER);

  std::vector<uint8_t> stored_key;
  ASSERT_TRUE(storage->load("private_key", stored_key)) << "Pairing should persist the generated private key";
  ASSERT_FALSE(stored_key.empty()) << "Persisted private key should not be empty";

  auto expected_public_key = derive_public_key_from_private_key(stored_key);
  ASSERT_FALSE(expected_public_key.empty()) << "Persisted private key should produce a public key";

  vehicle->loop();
  vehicle->loop();

  const auto &writes = ble->get_written_data();
  ASSERT_EQ(writes.size(), 1U) << "Pairing should send one direct whitelist request without a session auth handshake";

  VCSEC_PermissionChange permissions = VCSEC_PermissionChange_init_default;
  VCSEC_KeyFormFactor form_factor = VCSEC_KeyFormFactor_KEY_FORM_FACTOR_UNKNOWN;
  VCSEC_SignatureType signature_type = VCSEC_SignatureType_SIGNATURE_TYPE_NONE;
  ASSERT_TRUE(parse_whitelist_message(writes.front(), &permissions, &form_factor, &signature_type))
      << "First pairing write should be a VCSEC whitelist command";

  EXPECT_EQ(signature_type, VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY);
  EXPECT_EQ(form_factor, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_NFC_CARD);
  EXPECT_EQ(permissions.keyRole, Keys_Role_ROLE_DRIVER);
  ASSERT_EQ(permissions.key.PublicKeyRaw.size, expected_public_key.size());
  EXPECT_TRUE(std::equal(expected_public_key.begin(), expected_public_key.end(), permissions.key.PublicKeyRaw.bytes));
}

TEST_F(VehicleTest, PairingWhitelistRequestUsesCommandTimeout) {
  vehicle_->set_connected(true);
  vehicle_->pair();
  vehicle_->loop();

  auto &command_queue = const_cast<std::queue<std::shared_ptr<Command>> &>(vehicle_->get_command_queue_for_testing());
  ASSERT_FALSE(command_queue.empty()) << "Pairing command should remain pending while waiting for a response";

  auto command = command_queue.front();
  ASSERT_NE(command, nullptr);
  ASSERT_EQ(command->name, "Whitelist Add Key");

  command->state = CommandState::WAITING_FOR_RESPONSE;
  command->retry_count = 0;
  command->started_at = std::chrono::steady_clock::now() - Vehicle::CLOCK_SYNC_MAX_LATENCY - std::chrono::seconds(1);
  command->last_tx_at = command->started_at;

  mock_ble_->clear_written_data();
  vehicle_->loop();

  EXPECT_EQ(command->retry_count, 0) << "Whitelist pairing should not retry at the normal clock sync timeout";
  EXPECT_EQ(command->state, CommandState::WAITING_FOR_RESPONSE);
  EXPECT_TRUE(mock_ble_->get_written_data().empty()) << "No retry write should occur before command timeout";
}

TEST_F(VehicleTest, InfotainmentWakeTransitionResetsCommandTimeoutBudget) {
  vehicle_->set_connected(true);

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Infotainment Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      nullptr, true);

  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "Should send initial VCSEC session info request";
  size_t vcsec_request_uuid_length = 0;
  auto vcsec_request_uuid = extract_request_uuid(writes.front(), &vcsec_request_uuid_length);
  ASSERT_EQ(vcsec_request_uuid_length, vcsec_request_uuid.size());

  auto vcsec_session = make_vcsec_session_info_with_valid_hmac(vcsec_request_uuid.data(), vcsec_request_uuid_length);
  ASSERT_FALSE(vcsec_session.empty()) << "Should build VCSEC session response";
  vehicle_->on_rx_data(vcsec_session);
  vehicle_->loop();

  auto &command_queue = const_cast<std::queue<std::shared_ptr<Command>> &>(vehicle_->get_command_queue_for_testing());
  ASSERT_FALSE(command_queue.empty()) << "Infotainment command should be pending";

  auto command = command_queue.front();
  ASSERT_NE(command, nullptr);
  ASSERT_EQ(command->domain, UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  ASSERT_EQ(command->state, CommandState::AUTH_RESPONSE_WAITING);

  // Simulate most of the total command budget being spent before an awake status arrives.
  command->started_at = std::chrono::steady_clock::now() - Vehicle::COMMAND_TIMEOUT + std::chrono::seconds(1);

  mock_ble_->clear_written_data();

  auto awake_status = make_vcsec_vehicle_status_awake_message();
  ASSERT_FALSE(awake_status.empty()) << "Should build VCSEC vehicle status wake message";
  vehicle_->on_rx_data(awake_status);
  vehicle_->loop();

  ASSERT_FALSE(command_queue.empty()) << "Command should not time out immediately after wake confirmation";
  EXPECT_EQ(command->state, CommandState::AUTH_RESPONSE_WAITING)
      << "Wake confirmation should advance directly into infotainment session auth";

  writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "Vehicle should send infotainment session info request after wake transition";

  size_t request_uuid_length = 0;
  auto request_uuid = extract_request_uuid(writes.back(), &request_uuid_length);
  ASSERT_EQ(request_uuid_length, request_uuid.size());

  auto infotainment_session = make_infotainment_session_info_with_valid_hmac(request_uuid.data(), request_uuid_length);
  ASSERT_FALSE(infotainment_session.empty()) << "Should build infotainment session response";
  vehicle_->on_rx_data(infotainment_session);
  vehicle_->loop();

  ASSERT_FALSE(command_queue.empty()) << "Command should still be pending until the poll response arrives";
  EXPECT_EQ(command->state, CommandState::WAITING_FOR_RESPONSE)
      << "Successful session info response should allow the poll to be sent instead of timing out";
}

// ============================================================================
// Session Recovery: ERROR_TIME_EXPIRED triggers peer reset and re-auth
// ============================================================================

// Helper: build a signed message error response with ERROR_TIME_EXPIRED fault
// and embedded session_info bytes from a pre-parsed mock message.
static std::vector<uint8_t> make_error_time_expired_message(UniversalMessage_Domain domain) {
  // Parse the mock VCSEC message to extract the raw session_info protobuf bytes
  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage mock_msg = UniversalMessage_RoutableMessage_init_default;
  auto status = parser.parse_universal_message(const_cast<pb_byte_t *>(MOCK_VCSEC_MESSAGE), sizeof(MOCK_VCSEC_MESSAGE),
                                               &mock_msg);
  if (status != TeslaBLE_Status_E_OK) {
    return {};
  }

  UniversalMessage_RoutableMessage error_msg = UniversalMessage_RoutableMessage_init_default;

  // Set origin domain (vehicle is responding)
  error_msg.has_from_destination = true;
  error_msg.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  error_msg.from_destination.sub_destination.domain = domain;

  // Signal an ERROR_TIME_EXPIRED fault
  error_msg.has_signedMessageStatus = true;
  error_msg.signedMessageStatus.operation_status = UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR;
  error_msg.signedMessageStatus.signed_message_fault = UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED;

  // Embed the raw session_info bytes (re-use from mock message)
  // The HMAC will not verify (wrong UUID), but that's fine —
  // the peer was already reset so the command retries with fresh auth.
  error_msg.which_payload = UniversalMessage_RoutableMessage_session_info_tag;
  std::copy_n(mock_msg.payload.session_info.bytes, mock_msg.payload.session_info.size,
              error_msg.payload.session_info.bytes);
  error_msg.payload.session_info.size = mock_msg.payload.session_info.size;

  return frame_universal_message(error_msg);
}

TEST_F(VehicleTest, ErrorTimeExpiredTriggersSessionResetAndReAuth) {
  // Desired behaviour: when the vehicle indicates the session has expired,
  // the client recovers by re-establishing the session — without a restart.
  //
  // This verifies that ERROR_TIME_EXPIRED resets the peer (so subsequent
  // retries go through fresh authentication) rather than leaving the stale
  // session in place where retries would keep failing.

  vehicle_->set_connected(true);

  // Send a VCSEC poll command
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Poll",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 4;
        std::fill_n(buffer, 4, 0x42);
        return TeslaBLE_Status_E_OK;
      },
      nullptr,
      false);  // poll commands don't require wake

  vehicle_->loop();

  // Step 1 — initial auth: vehicle sends session info request
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "Should send session info request";
  size_t req_uuid_len = 0;
  auto req_uuid = extract_request_uuid(writes[0], &req_uuid_len);
  ASSERT_EQ(req_uuid_len, 16);

  // Step 2 — establish session with valid HMAC response
  auto session_resp = make_vcsec_session_info_with_valid_hmac(req_uuid.data(), req_uuid_len);
  ASSERT_GT(session_resp.size(), 0);
  vehicle_->on_rx_data(session_resp);
  vehicle_->loop();

  // Step 3 — command should be sent (encrypted, now that session is valid)
  auto writes_before = mock_ble_->get_written_data();
  ASSERT_GT(writes_before.size(), writes.size()) << "Should send command after auth";

  // Step 4 — inject ERROR_TIME_EXPIRED response
  auto error_frame = make_error_time_expired_message(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_GT(error_frame.size(), 0) << "Should build error message";

  mock_ble_->clear_written_data();
  vehicle_->on_rx_data(error_frame);
  vehicle_->loop();

  // Step 5 — recovery: must send a NEW session info request
  // (proving the peer was reset on ERROR_TIME_EXPIRED)
  auto recovery_writes = mock_ble_->get_written_data();
  ASSERT_GE(recovery_writes.size(), 1) << "Should send new session info request after ERROR_TIME_EXPIRED";

  size_t recovery_uuid_len = 0;
  auto recovery_uuid = extract_request_uuid(recovery_writes[0], &recovery_uuid_len);
  ASSERT_EQ(recovery_uuid_len, 16) << "Recovery should start with fresh session info request";

  // Step 6 — complete recovery with valid HMAC response for the new request
  auto recovery_session_resp = make_vcsec_session_info_with_valid_hmac(recovery_uuid.data(), recovery_uuid_len);
  ASSERT_GT(recovery_session_resp.size(), 0);
  vehicle_->on_rx_data(recovery_session_resp);
  vehicle_->loop();

  // Step 7 — command retried and sent after recovery
  // (callback won't fire here because we don't inject a response for
  // the dummy command body; the recovery itself is the important part)
  auto final_writes = mock_ble_->get_written_data();
  ASSERT_GT(final_writes.size(), recovery_writes.size()) << "Command should be re-sent after session recovery";
}

// ============================================================================
// Session Info HMAC Tag Handling Tests (Issue #164)
// ============================================================================

TEST_F(VehicleTest, MissingSessionInfoHmacTagFailsAuthGracefully) {
  bool callback_called = false;
  std::unique_ptr<CommandError> captured_error;

  vehicle_->set_connected(true);

  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Command",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 4;
        std::fill_n(buffer, 4, 0x42);
        return TeslaBLE_Status_E_OK;
      },
      [&](std::unique_ptr<CommandError> error) {
        callback_called = true;
        if (error) {
          captured_error = std::move(error);
        }
      });

  vehicle_->loop();
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "Should send session info request";
  mock_ble_->clear_written_data();

  auto no_hmac_resp = make_session_info_no_hmac_tag(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_FALSE(no_hmac_resp.empty()) << "Should build no-HMAC session info response";

  vehicle_->on_rx_data(no_hmac_resp);
  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "Command callback should be invoked";
  ASSERT_NE(captured_error, nullptr) << "Command should fail with error";
  EXPECT_TRUE(captured_error->message().find("authentication failed") != std::string::npos)
      << "Error should indicate auth failure: " << captured_error->message();

  EXPECT_TRUE(mock_ble_->get_written_data().empty()) << "No additional writes should occur after auth failure";
}

TEST_F(VehicleTest, MissingSessionInfoHmacTagDoesNotBlockSubsequentCommands) {
  bool first_callback_called = false;

  vehicle_->set_connected(true);

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "First Command",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 4;
        std::fill_n(buffer, 4, 0x42);
        return TeslaBLE_Status_E_OK;
      },
      [&](bool) { first_callback_called = true; });

  vehicle_->loop();
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);
  mock_ble_->clear_written_data();

  auto no_hmac_resp = make_session_info_no_hmac_tag(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_FALSE(no_hmac_resp.empty());
  vehicle_->on_rx_data(no_hmac_resp);
  vehicle_->loop();
  ASSERT_TRUE(first_callback_called) << "First command should fail";

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Second Command",
      [](Client *, uint8_t *buffer, size_t *len) {
        *len = 4;
        std::fill_n(buffer, 4, 0x42);
        return TeslaBLE_Status_E_OK;
      },
      nullptr);

  vehicle_->loop();
  writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "Second command should send a new session info request";
  size_t second_uuid_len = 0;
  auto second_uuid = extract_request_uuid(writes.back(), &second_uuid_len);
  ASSERT_EQ(second_uuid_len, 16);

  auto valid_session = make_vcsec_session_info_with_valid_hmac(second_uuid.data(), second_uuid_len);
  ASSERT_FALSE(valid_session.empty());
  mock_ble_->clear_written_data();
  vehicle_->on_rx_data(valid_session);
  vehicle_->loop();

  auto writes_after = mock_ble_->get_written_data();
  ASSERT_GE(writes_after.size(), 1) << "Second command should be sent after valid auth";
}

TEST_F(VehicleTest, PairingBypassesAuthEvenWhenVcsecAuthIsFailing) {
  vehicle_->set_connected(true);

  bool poll_failed = false;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "VCSEC Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_information_request_message(
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, buff, len);
      },
      [&](bool success) { poll_failed = !success; });

  vehicle_->loop();
  mock_ble_->clear_written_data();

  auto no_hmac_resp = make_session_info_no_hmac_tag(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_FALSE(no_hmac_resp.empty());
  vehicle_->on_rx_data(no_hmac_resp);
  vehicle_->loop();
  ASSERT_TRUE(poll_failed) << "VCSEC poll should fail due to missing HMAC tag";

  vehicle_->pair();

  vehicle_->loop();
  vehicle_->loop();

  const auto &writes = mock_ble_->get_written_data();
  ASSERT_EQ(writes.size(), 1U) << "Pairing should send one direct whitelist request without any session auth handshake";
  VCSEC_SignatureType signature_type = VCSEC_SignatureType_SIGNATURE_TYPE_NONE;
  ASSERT_TRUE(parse_whitelist_message(writes.front(), nullptr, nullptr, &signature_type));
  EXPECT_EQ(signature_type, VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY);
}

// ============================================================================
// Wake Policy Regression Tests (4.1)
// ============================================================================

TEST_F(VehicleTest, NoWakeSkipSkipsWhenVehicleAsleep) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  bool callback_called = false;
  bool callback_success = false;

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "NoWakeSkip Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      },
      TeslaBLE::WakePolicy::NoWakeSkip);

  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "NoWakeSkip should invoke callback immediately";
  ASSERT_TRUE(callback_success) << "NoWakeSkip should report compatible_success for skipped";
  auto writes = mock_ble_->get_written_data();
  EXPECT_EQ(writes.size(), 0) << "NoWakeSkip should not send BLE data when asleep";
}

TEST_F(VehicleTest, NoWakeFailWhenVehicleAsleep) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  bool callback_called = false;
  bool callback_success = true;

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "NoWakeFail Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      },
      TeslaBLE::WakePolicy::NoWakeFail);

  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "NoWakeFail should invoke callback immediately";
  ASSERT_FALSE(callback_success) << "NoWakeFail should report failure for asleep vehicle";
  auto writes = mock_ble_->get_written_data();
  EXPECT_EQ(writes.size(), 0) << "NoWakeFail should not send BLE data when asleep";
}

TEST_F(VehicleTest, WakeIfNeededProceedsWhenAwake) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Awake);

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "WakeIfNeeded Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      nullptr, TeslaBLE::WakePolicy::WakeIfNeeded);

  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "WakeIfNeeded with awake vehicle should start auth";
}

TEST_F(VehicleTest, WakeIfNeededTriggersWakeWhenAsleep) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "WakeIfNeeded Asleep",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      nullptr, TeslaBLE::WakePolicy::WakeIfNeeded);

  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1) << "WakeIfNeeded with asleep vehicle should send VCSEC auth before wake";
}

TEST_F(VehicleTest, WakePolicyRichOutcomeCallbackDistinguishesSkipped) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  bool callback_called = false;
  TeslaBLE::OperationOutcome captured_outcome = TeslaBLE::OperationOutcome::Failed;
  TeslaBLE::OperationTerminalReason captured_reason = TeslaBLE::OperationTerminalReason::None;

  vehicle_->send_command_result(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Result Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](TeslaBLE::OperationResult result) {
        callback_called = true;
        captured_outcome = result.outcome();
        captured_reason = result.reason();
      },
      TeslaBLE::WakePolicy::NoWakeSkip);

  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "Rich callback should be invoked";
  EXPECT_EQ(captured_outcome, TeslaBLE::OperationOutcome::Skipped);
  EXPECT_EQ(captured_reason, TeslaBLE::OperationTerminalReason::VehicleAsleep);
}

TEST_F(VehicleTest, WakePolicyRichOutcomeCallbackDistinguishesFailed) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  bool callback_called = false;
  TeslaBLE::OperationOutcome captured_outcome = TeslaBLE::OperationOutcome::Success;

  vehicle_->send_command_result(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Fail Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](TeslaBLE::OperationResult result) {
        callback_called = true;
        captured_outcome = result.outcome();
      },
      TeslaBLE::WakePolicy::NoWakeFail);

  vehicle_->loop();

  ASSERT_TRUE(callback_called) << "Rich callback should be invoked";
  EXPECT_EQ(captured_outcome, TeslaBLE::OperationOutcome::Failed);
}

// ============================================================================
// Step-Specific Timeout Regression Tests (4.2)
// ============================================================================

TEST_F(VehicleTest, WakePhaseTimeoutDoesNotConsumeFinalResponseBudget) {
  vehicle_->set_connected(true);

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Post-Wake Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      nullptr, true);

  vehicle_->loop();

  // Establish VCSEC session
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);
  size_t vcsec_uuid_len = 0;
  auto vcsec_uuid = extract_request_uuid(writes.front(), &vcsec_uuid_len);
  ASSERT_EQ(vcsec_uuid_len, vcsec_uuid.size());
  auto vcsec_session = make_vcsec_session_info_with_valid_hmac(vcsec_uuid.data(), vcsec_uuid_len);
  ASSERT_FALSE(vcsec_session.empty());
  vehicle_->on_rx_data(vcsec_session);
  vehicle_->loop();

  // At this point, sleep state is Unknown and WakeIfNeeded initiates wake.
  // Simulate the wake phase timing out without a response.
  auto &command_queue = const_cast<std::queue<std::shared_ptr<Command>> &>(vehicle_->get_command_queue_for_testing());
  ASSERT_FALSE(command_queue.empty());
  auto command = command_queue.front();
  ASSERT_NE(command, nullptr);

  // Command should be in AUTH_RESPONSE_WAITING for the wake phase
  EXPECT_EQ(command->state, TeslaBLE::CommandState::AUTH_RESPONSE_WAITING);
  EXPECT_EQ(command->phase, TeslaBLE::OperationPhase::EnsuringAwake);

  // Advance time to exhaust wake-phase timeout but leave total command budget untouched.
  // Wake timeout is measured from last_tx_at (when wake command was actually sent).
  command->last_tx_at =
      std::chrono::steady_clock::now() - TeslaBLE::Vehicle::AUTH_RESPONSE_TIMEOUT - std::chrono::seconds(1);
  mock_ble_->clear_written_data();
  vehicle_->loop();

  // Wake timeout should trigger retry (state back to IDLE), not command failure
  EXPECT_EQ(command->state, TeslaBLE::CommandState::IDLE) << "Wake timeout should trigger retry, not command failure";
  ASSERT_FALSE(command_queue.empty()) << "Command should remain in queue after retry (not finalized)";
}

TEST_F(VehicleTest, AuthPhaseTimeoutIndependentFromFinalResponseTimeout) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Awake);

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Auth Timeout Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      nullptr, true);

  vehicle_->loop();

  // Auth request should be sent
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);
  mock_ble_->clear_written_data();

  auto &command_queue = const_cast<std::queue<std::shared_ptr<Command>> &>(vehicle_->get_command_queue_for_testing());
  ASSERT_FALSE(command_queue.empty());
  auto command = command_queue.front();

  EXPECT_EQ(command->phase, TeslaBLE::OperationPhase::EnsuringVcsecSession);

  // Advance time past auth timeout
  command->phase_started_at =
      std::chrono::steady_clock::now() - TeslaBLE::Vehicle::AUTH_RESPONSE_TIMEOUT - std::chrono::seconds(1);
  vehicle_->loop();

  // Auth timeout should trigger retry, not final command failure
  ASSERT_FALSE(command_queue.empty()) << "Command should remain in queue after auth retry";
  EXPECT_NE(command->state, TeslaBLE::CommandState::FAILED) << "Auth phase timeout should retry, not fail the command";
}

// ============================================================================
// Wrapper Outcome Distinction Tests (4.3)
// ============================================================================

TEST_F(VehicleTest, WrapperCanObserveSkippedOutcomeWithoutInspectingInternals) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  TeslaBLE::OperationOutcome outcome = TeslaBLE::OperationOutcome::Failed;
  TeslaBLE::OperationTerminalReason reason = TeslaBLE::OperationTerminalReason::None;
  const TeslaBLE::CommandError *err = nullptr;

  vehicle_->send_command_result(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Wrapper Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](TeslaBLE::OperationResult result) {
        outcome = result.outcome();
        reason = result.reason();
        err = result.error();
      },
      TeslaBLE::WakePolicy::NoWakeSkip);

  vehicle_->loop();

  EXPECT_EQ(outcome, TeslaBLE::OperationOutcome::Skipped);
  EXPECT_EQ(reason, TeslaBLE::OperationTerminalReason::VehicleAsleep);
  EXPECT_EQ(err, nullptr) << "Skipped operations should not carry an error";
}

TEST_F(VehicleTest, WrapperCanObservePhaseTransitions) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Awake);

  std::vector<TeslaBLE::OperationPhase> phases;
  TeslaBLE::OperationOutcome outcome = TeslaBLE::OperationOutcome::Failed;

  vehicle_->send_command_result(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Phase Observed Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](TeslaBLE::OperationResult result) { outcome = result.outcome(); }, TeslaBLE::WakePolicy::WakeIfNeeded,
      [&](TeslaBLE::OperationPhase phase) { phases.push_back(phase); });

  vehicle_->loop();

  ASSERT_GE(phases.size(), 1) << "Phase callback should fire at least once";
  EXPECT_EQ(phases.front(), TeslaBLE::OperationPhase::Queued) << "First phase should be Queued";

  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);
  size_t vcsec_uuid_len = 0;
  auto vcsec_uuid = extract_request_uuid(writes.front(), &vcsec_uuid_len);
  ASSERT_EQ(vcsec_uuid_len, vcsec_uuid.size());
  auto vcsec_session = make_vcsec_session_info_with_valid_hmac(vcsec_uuid.data(), vcsec_uuid_len);
  ASSERT_FALSE(vcsec_session.empty());
  vehicle_->on_rx_data(vcsec_session);
  vehicle_->loop();

  ASSERT_GE(phases.size(), 2) << "Should see Queued → EnsuringVcsecSession → EnsuringInfotainmentSession phases";
  EXPECT_EQ(phases[1], TeslaBLE::OperationPhase::EnsuringVcsecSession);
}

TEST_F(VehicleTest, WrapperCompatibleSuccessPreservesExistingBoolSemantics) {
  vehicle_->set_connected(true);
  vehicle_->set_sleep_state(TeslaBLE::SleepState::Asleep);

  bool callback_called = false;
  bool callback_success = false;

  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Compat Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      },
      TeslaBLE::WakePolicy::NoWakeSkip);

  vehicle_->loop();

  ASSERT_TRUE(callback_called);
  ASSERT_TRUE(callback_success) << "compatible_success should be true for skipped operations";
  auto writes = mock_ble_->get_written_data();
  EXPECT_EQ(writes.size(), 0) << "No BLE writes should occur for skipped NoWakeSkip";
}

// ============================================================================
// Command Struct Tests
// ============================================================================

TEST(CommandStructTest, DefaultRequiresWakeIsTrue) {
  Command cmd(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Command",
      [](Client *, uint8_t *, size_t *) { return TeslaBLE_Status_E_OK; }, nullptr);

  ASSERT_EQ(cmd.wake_policy, TeslaBLE::WakePolicy::WakeIfNeeded)
      << "Commands should default to requiring wake for safety";
}

TEST(CommandStructTest, RequiresWakeCanBeSetFalse) {
  Command cmd(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Poll",
      [](Client *, uint8_t *, size_t *) { return TeslaBLE_Status_E_OK; }, nullptr, TeslaBLE::WakePolicy::NoWakeSkip);

  ASSERT_EQ(cmd.wake_policy, TeslaBLE::WakePolicy::NoWakeSkip);
}

// ============================================================================
// Internal Helper Tests (for regression testing specific fixes)
// These tests verify internal invariants that prevent data corruption.
// ============================================================================

// Friend test helper exposing protected members for regression testing
class VehicleTestHelper : public Vehicle {
 public:
  using Vehicle::get_expected_message_length;
  using Vehicle::rx_buffer_;

  VehicleTestHelper(const std::shared_ptr<BleAdapter> &b, const std::shared_ptr<StorageAdapter> &s) : Vehicle(b, s) {}

  void set_buffer(const std::vector<uint8_t> &data) { rx_buffer_ = data; }
};

class VehicleInternalTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_ble_ = std::make_shared<MockBleAdapter>();
    mock_storage_ = std::make_shared<MockStorageAdapter>();

    size_t key_length = 0;
    while (CLIENT_PRIVATE_KEY_PEM[key_length] != '\0')
      ++key_length;
    std::vector<uint8_t> key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM),
                             reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM) + key_length + 1);
    mock_storage_->set_data("private_key", key);

    vehicle_ = std::make_shared<VehicleTestHelper>(mock_ble_, mock_storage_);
    vehicle_->set_vin(TEST_VIN);
    vehicle_->set_connected(true);
    vehicle_->set_awake(true);
  }

  std::shared_ptr<MockBleAdapter> mock_ble_;
  std::shared_ptr<MockStorageAdapter> mock_storage_;
  std::shared_ptr<VehicleTestHelper> vehicle_;
};

TEST_F(VehicleInternalTest, ExpectedLengthIncludesHeader) {
  std::vector<uint8_t> data = {0x00, 0x0A};
  vehicle_->set_buffer(data);

  EXPECT_EQ(vehicle_->get_expected_message_length(), 12);
}

TEST_F(VehicleInternalTest, CommandCompletesAfterTimeoutWithPartialData) {
  bool completed = false;
  bool success = false;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Command",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool ok) {
        completed = true;
        success = ok;
      },
      true);

  vehicle_->loop();
  auto writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 1);
  size_t uuid_len = 0;
  auto uuid = extract_request_uuid(writes.front(), &uuid_len);
  ASSERT_EQ(uuid_len, uuid.size());

  vehicle_->on_rx_data(make_vcsec_session_info_with_valid_hmac(uuid.data(), uuid_len));
  vehicle_->loop();

  writes = mock_ble_->get_written_data();
  ASSERT_GE(writes.size(), 2);
  uuid = extract_request_uuid(writes.back(), &uuid_len);
  ASSERT_EQ(uuid_len, uuid.size());
  vehicle_->on_rx_data(make_infotainment_session_info_with_valid_hmac(uuid.data(), uuid_len));
  vehicle_->loop();

  auto &cmd_queue = const_cast<std::queue<std::shared_ptr<Command>> &>(vehicle_->get_command_queue_for_testing());
  ASSERT_FALSE(cmd_queue.empty());
  auto cmd = cmd_queue.front();
  ASSERT_EQ(cmd->state, CommandState::WAITING_FOR_RESPONSE);

  vehicle_->on_rx_data({0xFF});
  ASSERT_FALSE(vehicle_->rx_buffer_.empty());

  cmd->retry_count = 0;
  cmd->last_tx_at = std::chrono::steady_clock::now() - std::chrono::seconds(5);
  mock_ble_->clear_written_data();
  vehicle_->loop();

  EXPECT_TRUE(vehicle_->rx_buffer_.empty());
  EXPECT_EQ(cmd->state, CommandState::READY);

  vehicle_->loop();
  vehicle_->on_rx_data(make_plain_infotainment_response());
  vehicle_->loop();

  ASSERT_TRUE(completed);
  ASSERT_TRUE(success);
}
